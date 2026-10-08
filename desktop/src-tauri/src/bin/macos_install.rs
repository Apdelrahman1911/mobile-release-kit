//! One-shot scripts-only standard Installer entry. Installer never lays files
//! into the final app/runtime destinations. One original parent admits the
//! completed package; its exact self-worker owns the existing copy writer.
//! No Python, app, daemon or general publisher runs as root.
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
        macos_install_record::{self as installation_record, Entry, Inventory},
        macos_install_maintenance::{ActionData, ReleaseSetData},
        macos_install_transaction as transaction, runtime::safe_payload_path};
    use mrk_macos_installed_native as native;
    type Result<T> = std::result::Result<T, &'static str>;
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown, KernelExitRetained }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Role { Reader, PayloadWriter, MetadataWriter, ReceiptWriter, GateWriter, GateParticipant, ReservationWriter, ReservationParticipant }
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
    // R is independent of M: never overwrite the lifetime maintenance participant.
    // These fields record actual original calls, not authority decoded from DATA.
    struct RegistrationReservation {
        entered: bool, creation: &'static str, written: u64, sealed: bool, persisted: bool, parent_persisted: bool,
        parent: Option<usize>, writer: Option<usize>, participant: Option<usize>, verified: bool,
        lock_attempted: bool, exclusive_acquired: bool, closed_under_maintenance: bool, verified_after_go: bool,
    }
    impl RegistrationReservation {
        fn new() -> Self { Self { entered:false,creation:"not-attempted",written:0,sealed:false,persisted:false,
            parent_persisted:false,parent:None,writer:None,participant:None,verified:false,
            lock_attempted:false,exclusive_acquired:false,closed_under_maintenance:false,verified_after_go:false } }
    }
    struct Install {
        originals: Vec<Original>, creations: Vec<Creation>, end: Instant, unknown: bool,
        // `end` remains the original legacy-entry clock. The private B2 path
        // never uses it: both processes receive this same absolute deadline.
        worker_deadline: Option<worker::Deadline>, worker_stderr_is_gate: bool, worker_go_eof: bool,
        // Zero for all ordinary install/worker/fixture paths. The removal
        // Parent debits native peer and retained-source costs in the SAME book.
        removal_live_reserved: usize, removal_control_reserved: u64,
        removal_snapshot_capture: Option<maintenance::RemovalSnapshotCapture>,
        removal_snapshot_work_reserved: bool,
        removal_payload_plan:Option<maintenance::RemovalPayloadPlan>,
        removal_observation_control:Option<u64>,removal_observation_reserved:u64,
        removal_archive_scan: Option<maintenance::RemovalArchiveScan>,
        payload_written: u64, payload_write_calls: u64,
        stage: Option<usize>, stage_name: Option<String>, app: Option<usize>, runtime: Option<usize>,
        runtime_publication: &'static str, app_publication: &'static str, payload_verified: bool,
        metadata: installation_record::Progress,
        gate: MaintenanceGate,
        registration: RegistrationReservation,
        // Actual native observations of the one B3 writer, never parsed action authority.
        maintenance: Option<maintenance::Effects>,
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
    // Comparison DATA only. The caller still must check the actual retained
    // gate.parent original and the independently opened named reader below.
    fn installed_root_roster_alias_data(admitted:Identity, held:Identity, reader:Identity,
        held_flags:u32, reader_flags:u32)->bool {
        admitted.same_object(held) && admitted.mode==held.mode && held==reader
            && held.mode==0o040755 && held.uid==0 && held.gid==0
            && held_flags==0 && reader_flags==0
    }
    fn installed_root_roster_child_data(name:&str,actual_root_alias:bool)->bool {
        component(name) || actual_root_alias && name==paths::APP_NAME
    }
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
                removal_live_reserved:0,removal_control_reserved:0,removal_snapshot_capture:None,removal_snapshot_work_reserved:false,removal_payload_plan:None,removal_observation_control:None,removal_observation_reserved:0,removal_archive_scan:None,
                stage:None,stage_name:None,app:None,runtime:None,runtime_publication:"not-attempted",app_publication:"not-attempted",payload_verified:false,
                metadata:installation_record::Progress::default(),
                gate:MaintenanceGate::new(),registration:RegistrationReservation::new(),maintenance:None,
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
            let extra = (if self.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 })
                + self.removal_live_reserved;
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
                    if self.originals[n].role == Role::ReservationWriter { self.registration.creation = "created"; }
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
            if role == Role::ReservationParticipant { self.registration.participant = Some(n); }
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
            if role == Role::ReservationWriter { self.registration.writer = Some(n); self.registration.creation = "attempting"; }
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
            if file && self.originals[n].role == Role::ReservationWriter { self.registration.persisted = true; }
            if !file && self.registration.parent == Some(n) && self.registration.writer.is_some() { self.registration.parent_persisted = true; }
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
                if self.originals[n].role == Role::ReservationWriter {
                    self.registration.written = self.registration.written.checked_add(count as u64).ok_or("registration-write-bound")?;
                    check(self.registration.written <= paths::REGISTRATION_GATE_BYTES.len() as u64, "registration-write-bound")?;
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
            if self.originals[n].role == Role::ReservationWriter { self.registration.sealed = true; }
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
                "maintenanceGate":self.gate_record(),"registrationReservation":self.registration_record(),
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
        // Gate.parent is the actually admitted fixed installed root, never an
        // input pathname or a caller-provided root flag. A separate roster FD
        // must name the SAME current directory, not just another root-owned one.
        fn installed_root_roster_alias(&self, reader:usize)->Result<bool> {
            let Some(root)=self.gate.parent else { return Ok(false); };
            self.check_name(root,false)?; self.check_name(reader,false)?;
            let held=stat::fstat(self.fd(root)?).map_err(|_|"roster-root-stat")?;
            let actual=stat::fstat(self.fd(reader)?).map_err(|_|"roster-reader-stat")?;
            let matched=installed_root_roster_alias_data(self.identity(root)?,Identity::of(&held),
                Identity::of(&actual),held.st_flags,actual.st_flags);
            // No baseline refresh. Existing current/source and exact-roster
            // checks still account for every actual own namespace change.
            self.check_name(root,false)?; self.check_name(reader,false)?;
            let held_post=stat::fstat(self.fd(root)?).map_err(|_|"roster-root-stat")?;
            let reader_post=stat::fstat(self.fd(reader)?).map_err(|_|"roster-reader-stat")?;
            check(Identity::of(&held_post)==Identity::of(&held) && held_post.st_flags==held.st_flags
                && Identity::of(&reader_post)==Identity::of(&actual) && reader_post.st_flags==actual.st_flags,
                "roster-root-post")?;
            Ok(matched)
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
                    let root_alias=if name==paths::APP_NAME { self.installed_root_roster_alias(n)? } else { false };
                    check(installed_root_roster_child_data(name,root_alias) && inode != 0 && found.len() < 4096
                        && found.insert(name.to_owned(), inode).is_none(), "directory-duplicate-or-bound")?;
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
        fn registration_protected(&self, reader: usize) -> Result<()> {
            check(self.registration.participant == Some(reader)
                && self.originals[reader].role == Role::ReservationParticipant
                && self.originals[reader].parent == self.registration.parent
                && self.originals[reader].name == paths::REGISTRATION_GATE_NAME, "registration-original")?;
            let parent = self.registration.parent.ok_or("registration-original")?;
            self.check_name(parent, false)?; self.protected(parent, true, Some(0o755))?;
            self.protected(reader, false, Some(0o444))?;
            let actual = stat::fstat(self.fd(reader)?).map_err(|_| "registration-stat")?;
            check(actual.st_flags == 0 && actual.st_size == paths::REGISTRATION_GATE_BYTES.len() as i64, "registration-shape")?;
            native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "registration-attributes")?;
            self.check_name(reader, true)
        }
        fn registration_open(&mut self, destination: usize) -> Result<usize> {
            check(self.registration.entered && self.registration.parent == Some(destination)
                && self.registration.participant.is_none(), "registration-original")?;
            let reader = self.open_role(Some(destination), paths::REGISTRATION_GATE_NAME, false, Role::ReservationParticipant)?;
            if let Some(writer) = self.registration.writer {
                check(self.identity(writer)?.same_object(self.identity(reader)?), "registration-created-correspondence")?;
            }
            self.registration_protected(reader)?;
            let (_, body) = self.read(reader, paths::REGISTRATION_GATE_BYTES.len() as u64, true)?;
            check(body == paths::REGISTRATION_GATE_BYTES, "registration-content")?;
            self.registration.verified = true;
            self.clock()?; Ok(reader)
        }
        fn registration_before_maintenance(&mut self, destination: usize) -> Result<()> {
            self.clock()?;
            check(!self.registration.entered && !self.gate.entered && !self.worker_stderr_is_gate,
                "registration-order")?;
            self.registration.entered = true; self.registration.parent = Some(destination);
            match self.named(Some(destination), paths::REGISTRATION_GATE_NAME) {
                Err(Errno::ENOENT) => { self.registration.creation = "absent-observed"; return Ok(()); },
                Ok(_) => self.registration.creation = "existing-not-modified",
                Err(_) => return Err("registration-name-refused"),
            }
            let reader = self.registration_open(destination)?;
            self.registration.lock_attempted = true;
            #[allow(deprecated)] // Borrow the original; never an early-unlocking Flock wrapper.
            let locked = fcntl::flock(self.fd(reader)?.as_raw_fd(), fcntl::FlockArg::LockExclusiveNonblock);
            locked.map_err(|_| "registration-busy-or-refused")?;
            self.registration.exclusive_acquired = true;
            self.clock()?; self.registration_protected(reader)
        }
        fn registration_complete_admitted(&mut self, destination: usize, action: ActionData) -> Result<()> {
            // Only two fixed callers: exact fresh roster, or fully authenticated
            // maintenance::observe + current incoming producer controls. No repair.
            self.clock()?;
            check(!self.worker_stderr_is_gate && self.registration.entered
                && self.registration.parent == Some(destination) && !self.registration.closed_under_maintenance,
                "registration-order")?;
            let maintenance = self.gate.participant.ok_or("registration-maintenance-required")?;
            check(self.gate.verified && self.gate.lock_attempted && self.gate.exclusive_acquired
                && self.gate.parent == Some(destination) && self.originals[maintenance].state == State::Owned,
                "registration-maintenance-required")?;
            self.gate_protected(maintenance)?;
            if self.registration.creation == "absent-observed" {
                // Same-current/no-op or restore of an R-capable release cannot
                // repair a missing reservation. Update was admitted from an
                // exact source-authorized predecessor by maintenance::observe.
                check(matches!(action, ActionData::FreshInstall | ActionData::Update), "registration-predecessor-required")?;
                check(self.registration.participant.is_none() && !self.registration.lock_attempted
                    && !self.registration.exclusive_acquired, "registration-order")?;
                self.absent(destination, paths::REGISTRATION_GATE_NAME)?;
                let writer = self.create_file(destination, paths::REGISTRATION_GATE_NAME, Role::ReservationWriter)?;
                self.write_all(writer, paths::REGISTRATION_GATE_BYTES)?;
                self.seal_file(writer, false)?; self.persist(destination, false)?;
                self.registration_open(destination)?;
            } else {
                check(self.registration.creation == "existing-not-modified" && self.registration.verified
                    && self.registration.lock_attempted && self.registration.exclusive_acquired,
                    "registration-order")?;
            }
            let reader = self.registration.participant.ok_or("registration-original")?;
            self.registration_protected(reader)?; self.gate_protected(maintenance)?;
            // Consume R only with the actual original M_EX already held. A
            // failed/unknown close bars all payload/worker effects; M stays last.
            check(self.close(reader), "registration-close-unknown")?;
            self.registration.closed_under_maintenance = true; // Returned close before possible late clock.
            self.clock()?; self.gate_protected(maintenance)?; self.registration_ready()
        }
        fn registration_after_go(&mut self, destination: usize) -> Result<()> {
            self.clock()?;
            check(self.worker_stderr_is_gate && self.worker_go_eof && self.worker_deadline.is_some()
                && !self.registration.entered && self.gate.verified && !self.gate.lock_attempted
                && !self.gate.exclusive_acquired && self.gate.parent == Some(destination), "registration-worker-go")?;
            self.registration.entered = true; self.registration.parent = Some(destination);
            self.registration.creation = "existing-not-modified";
            self.registration_open(destination)?;
            self.registration.verified_after_go = true;
            // The worker authenticates permanent R but NEVER claims its own EX.
            self.registration_ready()
        }
        fn registration_ready(&self) -> Result<()> {
            self.clock()?;
            let reader = self.registration.participant.ok_or("registration-finality-missing")?;
            check(self.registration.entered && self.registration.verified, "registration-finality-missing")?;
            let maintenance = self.gate.participant.ok_or("registration-maintenance-required")?;
            self.gate_protected(maintenance)?;
            if self.worker_stderr_is_gate {
                check(self.worker_go_eof && self.registration.verified_after_go
                    && !self.registration.lock_attempted && !self.registration.exclusive_acquired
                    && !self.registration.closed_under_maintenance, "registration-worker-go")?;
                self.registration_protected(reader)
            } else {
                check(self.gate.lock_attempted && self.gate.exclusive_acquired
                    && self.registration.closed_under_maintenance && !self.registration.verified_after_go
                    && self.originals[reader].state == State::Closed && self.originals[reader].fd.is_none(),
                    "registration-finality-missing")?;
                let parent = self.registration.parent.ok_or("registration-original")?;
                self.check_name(parent, false)?;
                let named = self.named(Some(parent), paths::REGISTRATION_GATE_NAME).map_err(|_| "registration-name-refused")?;
                check(Identity::of(&named) == self.identity(reader)? && named.st_flags == 0, "registration-closed-original")
            }
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
        fn registration_record(&self) -> serde_json::Value {
            let state = |index: Option<usize>| -> &'static str {
                match index.and_then(|i| self.originals.get(i)).map(|r| r.state) {
                    None => "not-attempted", Some(State::Reserved) => "reserved", Some(State::Acquiring) => "acquiring",
                    Some(State::Owned) => "owned", Some(State::NoHandle) => "no-handle", Some(State::Closing) => "closing",
                    Some(State::Closed) => "closed", Some(State::Unknown) => "unknown",
                    Some(State::KernelExitRetained) => "kernel-exit-retained",
                }
            };
            serde_json::json!({"schemaVersion":1,"entered":self.registration.entered,"creation":self.registration.creation,
                "fixedBytes":paths::REGISTRATION_GATE_BYTES.len(),"writtenBytes":self.registration.written,
                "sealed":self.registration.sealed,"filePersisted":self.registration.persisted,
                "parentPersisted":self.registration.parent_persisted,"writer":state(self.registration.writer),
                "verified":self.registration.verified,"exclusiveAttempted":self.registration.lock_attempted,
                "exclusiveAcquired":self.registration.exclusive_acquired,"participant":state(self.registration.participant),
                "closedUnderMaintenance":self.registration.closed_under_maintenance,"verifiedAfterGo":self.registration.verified_after_go,
                "cleanup":"original-closes-only-permanent-reservation-retained"})
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
                .and_then(|n| n.checked_add((paths::MAINTENANCE_GATE_BYTES.len() + paths::REGISTRATION_GATE_BYTES.len()) as u64))
                .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT), "inventory-bound")?;
            check(indexed.files.len().checked_add(4).is_some_and(|n| n <= installation_record::FILE_LIMIT), "installed-file-bound")?;
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
            self.registration_before_maintenance(destination)?;
            self.maintenance_gate(destination)?;
            maintenance::fresh_registration_roster(self, destination, versions)?;
            self.registration_complete_admitted(destination, ActionData::FreshInstall)?;
            Ok(PreparedFresh { input, inventory, inventory_bytes, destination, versions })
        }
        fn prepare_maintenance_input(&mut self, input: usize, inventory: Inventory, inventory_bytes: Vec<u8>) -> Result<PreparedFresh> {
            check(!cfg!(feature="macos-installed-installer-fixture"),"worker-fixture-route-unavailable")?;
            let index = inventory.index()?;
            check(index.payload_bytes.checked_add(inventory_bytes.len() as u64)
                .and_then(|n| n.checked_add(installation_record::RECORD_LIMIT as u64 + paths::MAINTENANCE_GATE_BYTES.len() as u64 + paths::REGISTRATION_GATE_BYTES.len() as u64))
                .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT)
                && index.files.len().checked_add(4).is_some_and(|n| n <= installation_record::FILE_LIMIT),"inventory-bound")?;
            let support = self.support_root()?;
            let destination = self.directory(support,"MobileReleaseKit",false,0o755)?;
            let versions = self.directory(destination,"versions",false,0o755)?;
            self.registration_before_maintenance(destination)?;
            self.maintenance_gate(destination)?;
            Ok(PreparedFresh { input,inventory,inventory_bytes,destination,versions })
        }
        fn install_prepared(&mut self, prepared: PreparedFresh, invocation: &str) -> Result<()> {
            check(!self.worker_stderr_is_gate || self.worker_go_eof, "worker-go-eof-required")?;
            check(worker::invocation_valid(invocation), "stage-identity")?;
            self.registration_ready()?;
            let (stage, app, runtime) = self.stage_payload(&prepared, invocation, true)?;
            let runtime = runtime.ok_or("stage-missing")?;
            let PreparedFresh { input: _, inventory: _, inventory_bytes, destination, versions } = prepared;
            // The fresh version parent is also exclusively created; failure
            // preserves an existing user's version and our unpublished staging.
            self.absent(destination, paths::APP_NAME)?;
            let release = self.directory(versions, paths::RELEASE, true, 0o755)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_runtime_publication(release)?;
            self.publish(runtime, stage, "runtime", release, "runtime", true)?;
            self.receipt("runtime-publication-confirmed")?;
            self.record_metadata(destination, release, invocation, &inventory_bytes)?;
            #[cfg(feature = "macos-installed-installer-fixture")]
            self.fixture_before_app_publication(destination)?;
            self.publish(app, stage, "app", destination, paths::APP_NAME, false)?;
            // Not an "installed/settled" receipt: remaining original descriptors
            // still have to close. Only final exit/output can report that fact.
            self.receipt("both-publications-confirmed")?; Ok(())
        }
        // Sole payload copier. Restore selects the App subset, never a second
        // publisher/copy engine. Legacy fresh still calls it once in the same order.
        fn stage_payload(&mut self, prepared: &PreparedFresh, invocation: &str, with_runtime: bool)
            -> Result<(usize, usize, Option<usize>)> {
            check(!self.worker_stderr_is_gate || self.worker_go_eof, "worker-go-eof-required")?;
            check(worker::invocation_valid(invocation), "stage-identity")?;
            let indexed = prepared.inventory.index()?;
            let name = format!(".install-{invocation}");
            self.stage_name = Some(name.clone()); // Reserve before the actual mkdir.
            let stage = self.directory(prepared.destination, &name, true, 0o700)?; self.stage = Some(stage);
            self.receipt("staging-created")?;
            let app = self.copy_tree("app", prepared.input, stage, &indexed.files, &indexed.directories, 0)?;
            self.app = Some(app);
            let runtime = if with_runtime {
                let original = self.copy_tree("runtime", prepared.input, stage, &indexed.files, &indexed.directories, 0)?;
                self.runtime = Some(original); Some(original)
            } else { None };
            self.check_name(prepared.input, true)?;
            check(self.payload_writers_settled() && !self.unknown, "writer-finality")?;
            self.payload_verified = true; self.persist(stage, false)?; self.receipt("prepared")?;
            Ok((stage, app, runtime))
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
            let reader = self.record_file(release, name, bytes, Role::MetadataWriter)?;
            self.forward_close(reader, "installation-readback-close")
        }
        // The caller chooses only a fixed metadata/evidence role. The returned
        // READ original remains held for a state swap or is consumed by caller.
        fn record_file(&mut self, release: usize, name: &str, bytes: &[u8], role: Role) -> Result<usize> {
            check(matches!(role, Role::MetadataWriter | Role::ReceiptWriter)
                && !bytes.is_empty() && bytes.len() <= transaction::CAPSULE_LIMIT.max(installation_record::INVENTORY_LIMIT),
                "installation-metadata-plan")?;
            let writer = self.create_file(release, name, role)?;
            self.record_reserved_file(writer, bytes)
        }
        fn record_reserved_file(&mut self, writer: usize, bytes: &[u8]) -> Result<usize> {
            check(matches!(self.originals[writer].role, Role::MetadataWriter | Role::ReceiptWriter)
                && !bytes.is_empty() && bytes.len() <= transaction::CAPSULE_LIMIT.max(installation_record::INVENTORY_LIMIT)
                && self.identity(writer)?.size == 0, "installation-metadata-plan")?;
            self.check_name(writer, true)?; self.protected(writer, false, Some(0o600))?;
            native::no_xattrs(self.fd(writer)?.as_fd()).map_err(|_| "installation-file-attributes")?;
            check(stat::fstat(self.fd(writer)?).map_err(|_| "installation-file-flags")?.st_flags == 0,
                "installation-file-flags")?;
            let release = self.originals[writer].parent.ok_or("installation-metadata-parent")?;
            let name = self.originals[writer].name.clone();
            self.write_all(writer, bytes)?; self.seal_file(writer, false)?;
            let reader = self.open(Some(release), &name, false)?;
            check(self.identity(writer)?.same_object(self.identity(reader)?), "installation-file-original")?;
            self.protected(reader, false, Some(0o444))?;
            native::no_xattrs(self.fd(reader)?.as_fd()).map_err(|_| "installation-file-attributes")?;
            check(stat::fstat(self.fd(reader)?).map_err(|_| "installation-file-flags")?.st_flags == 0,
                "installation-file-flags")?;
            let expected: String = format!("{:x}", Sha256::digest(bytes));
            check(self.read(reader, bytes.len() as u64, false)?.0 == expected, "installation-file-readback")?;
            check(stat::fstat(self.fd(reader)?).map_err(|_| "installation-file-flags")?.st_flags == 0,
                "installation-file-flags")?;
            Ok(reader)
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
            if result.is_ok() { result = self.registration_ready(); }
            let settled = self.settle_originals();
            // Sample AFTER every final close; an earlier Ok is not timely finality.
            match self.worker_deadline.as_ref() {
                Some(deadline) => {
                    let timely = deadline.check_total().is_ok();
                    if self.maintenance.is_some() { maintenance::finish(self,result,settled,timely) }
                    else { final_result_after_deadline(result, settled, self.unknown || deadline.is_unknown(),
                        self.runtime_publication, self.app_publication, timely) }
                }
                None => final_result(result, settled, self.unknown, self.runtime_publication, self.app_publication, self.end, Instant::now()),
            }
        }
        fn result_record(&self, result: &FinalResult) -> serde_json::Value {
            serde_json::json!({"schemaVersion":1,"state":result.state,"reason":result.reason,"release":paths::RELEASE,
                "runtimePublication":self.runtime_publication,"appPublication":self.app_publication,"staging":self.stage_name,
                "payloadVerified":self.payload_verified,"payloadWritersSettled":self.payload_writers_settled(),
                "installationMetadata":self.metadata.snapshot(self.metadata_writers_settled()),"originalsSettled":self.originals_settled(),
                "maintenanceGate":self.gate_record(),"registrationReservation":self.registration_record(),
                "deadlineMetAfterFinalCloses":result.deadline_met,"createdAncestors":self.creation_summary(),"cleanup":"original-closes-only-no-deletion",
                "sourceCommit":option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"),"inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"),
                "runtimeManifestSha256":option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")})
        }
    }
    // B3 shares the existing original descriptor book, copier and fixed roots.
    // None of these private DATA arguments authenticates a producer. The only
    // entry caller must first admit its genuine completed-package expectation.
    mod maintenance {
        use super::*;
        use transaction::{AppIdentityData, CapsuleData, CorrespondenceData, GenerationCostData,
            GenerationData, IntentData, ProgressData, ProgressOutcomeData, ReturnedData, StateData, StepData};

        pub(super) struct Effects {
            pub action: ActionData, pub progress: ProgressData,
            pub state: Option<StateData>, pub state_bytes: Option<Vec<u8>>,
            pub state_published: bool, pub inverse: bool,
        }
        pub(super) struct Recorded {
            pub intent: IntentData, pub state: StateData, pub capsule: CapsuleData,
        }
        pub(super) struct History {
            pub current: Recorded, pub originals: BTreeMap<String, Recorded>, pub state_original: usize,
            pub state_bytes: Vec<u8>, bytes: u64,
        }
        pub(super) struct Observed {
            pub prepared: PreparedFresh, pub selected: ReleaseSetData, pub action: ActionData,
            pub history: Option<History>, pub old_app: Option<usize>, pub old_release: Option<usize>,
            pub intent: Option<IntentData>, pub intent_original: Option<usize>,
            controls: Option<ProducerControls>,
        }
        // Same-book originals, not installed-file trust. An old pair is only
        // bounded retained DATA; the new package selects eligible generations.
        struct ProducerControls { originals: [usize;2], bytes: [Vec<u8>;2] }
        impl ProducerControls {
            fn post(&self, book: &Install) -> Result<()> {
                for (original, bytes) in self.originals.iter().zip(&self.bytes) { held_bytes(book,*original,bytes)?; }
                Ok(())
            }
            fn matches(&self, descriptor: &[u8], signature: &[u8]) -> bool {
                self.bytes[0] == descriptor && self.bytes[1] == signature
            }
            fn binding(&self, book: &Install) -> Result<serde_json::Value> {
                Ok(serde_json::json!({"descriptorOriginal":worker::identity_data(book.identity(self.originals[0])?),
                    "signatureOriginal":worker::identity_data(book.identity(self.originals[1])?),
                    "descriptorSha256":hash(&self.bytes[0]),"signatureSha256":hash(&self.bytes[1])}))
            }
        }
        fn data<T>(value: std::result::Result<T, transaction::TransactionDataError>) -> Result<T> {
            value.map_err(|_| "maintenance-record-binding")
        }
        fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
        pub(super) fn selected_compile(selected: &ReleaseSetData) -> Result<()> {
            let current = selected.current_data().binding_data();
            let target = if cfg!(target_arch = "aarch64") { "aarch64-apple-darwin" } else { "x86_64-apple-darwin" };
            check(selected.target_data().target() == target && current.release == paths::RELEASE
                && current.package_version == paths::PACKAGE_VERSION && current.protocol_sha256 == paths::PROTOCOL_SHA
                && Some(current.source_commit) == option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT")
                && Some(current.inventory_sha256) == option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256")
                && Some(current.runtime_manifest_sha256) == option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
                "maintenance-selected-compile")
        }
        // Removal-only preserved prefixes. These rows describe actual current
        // originals; no old inode/hash/0600 body grants a successful admission.
        const REMOVAL_ARCHIVE_COUNT:usize=64;
        const REMOVAL_ARCHIVE_TABLE:usize=128*1024;
        // Same2MiB reservation: one65KiB stream block (including return/move
        // overlap), bounded selected-release strict DATA/serde backing, two
        // previous names,64 prior references and the bounded root roster.
        const REMOVAL_ARCHIVE_PARSER:usize=1024*1024;
        const REMOVAL_HISTORY_SPANS:usize=256*1024;
        const REMOVAL_ARCHIVE_NAMES:[&str;6]=["snapshot-v2","admission.json","app-withdrawn.json",
            "payload-roster-removal.json","payload-absent-observed.json","first-failure.json"];
        #[derive(Clone,Copy,PartialEq,Eq)]
        enum RemovalArchiveShape { WritingPrefix, SealedBody }
        #[derive(PartialEq,Eq)]
        pub(super) struct RemovalArchiveFileReference {
            identity:Identity, flags:u32, len:u64, digest:[u8;32], shape:RemovalArchiveShape,
        }
        impl RemovalArchiveFileReference {
            pub(super) fn identity(&self)->Identity { self.identity }
            pub(super) fn flags(&self)->u32 { self.flags }
            pub(super) fn len(&self)->u64 { self.len }
            pub(super) fn digest(&self)->&[u8;32] { &self.digest }
            pub(super) fn shape_tag_data(&self)->u8 { match self.shape {
                RemovalArchiveShape::WritingPrefix=>1,RemovalArchiveShape::SealedBody=>2 } }
        }
        #[derive(PartialEq,Eq)]
        pub(super) struct RemovalArchiveReference {
            name:String,identity:Identity,flags:u32,files:[Option<RemovalArchiveFileReference>;6],
            app:Option<(Identity,u32)>,snapshot:Option<RemovalGenesisSummaryData>,attempt:Option<RemovalAttemptData>,
            // Only a completely observed header can supply an old request ID.
            // No unknown field is invented for an interrupted prefix.
            request:Option<[u8;16]>,
        }
        impl RemovalArchiveReference {
            pub(super) fn name(&self)->&str { &self.name }
            pub(super) fn identity(&self)->Identity { self.identity }
            pub(super) fn flags(&self)->u32 { self.flags }
            pub(super) fn files(&self)->&[Option<RemovalArchiveFileReference>;6] { &self.files }
            pub(super) fn app_data(&self)->Option<(Identity,u32)> {self.app}
            pub(super) fn attempt_data(&self)->Option<&RemovalAttemptData> {self.attempt.as_ref()}
        }
        #[derive(PartialEq,Eq)]
        pub(super) struct RemovalArchiveCensus { rows:Vec<RemovalArchiveReference>,storage_bytes:u64,root:usize }
        impl RemovalArchiveCensus {
            fn empty(root:usize)->Result<Self> {
                check(std::mem::size_of::<RemovalArchiveReference>().checked_mul(REMOVAL_ARCHIVE_COUNT)
                    .and_then(|n|n.checked_add(std::mem::size_of::<Self>())).is_some_and(|n|n<=REMOVAL_ARCHIVE_TABLE),
                    "removal-prior-memory")?;
                let mut rows=Vec::new();rows.try_reserve_exact(REMOVAL_ARCHIVE_COUNT).map_err(|_|"removal-prior-allocation")?;
                let value=Self {rows,storage_bytes:0,root};value.owned_bytes()?;Ok(value)
            }
            pub(super) fn rows(&self)->&[RemovalArchiveReference] { &self.rows }
            pub(super) fn storage_bytes(&self)->u64 { self.storage_bytes }
            pub(super) fn owned_bytes(&self)->Result<usize> {
                let mut count=std::mem::size_of::<Self>().checked_add(self.rows.capacity()
                    .checked_mul(std::mem::size_of::<RemovalArchiveReference>()).ok_or("removal-prior-memory")?)
                    .ok_or("removal-prior-memory")?;
                for row in &self.rows { count=count.checked_add(row.name.capacity()).ok_or("removal-prior-memory")?; }
                check(count<=REMOVAL_ARCHIVE_TABLE,"removal-prior-memory")?;Ok(count)
            }
            fn add(&mut self,row:RemovalArchiveReference)->Result<()> {
                check(self.rows.len()<REMOVAL_ARCHIVE_COUNT && self.rows.len()<self.rows.capacity()
                    && worker::removal_archive_name_data(&row.name)
                    && self.rows.last().is_none_or(|old|old.name<row.name),"removal-prior-count-order")?;
                let mut total=self.storage_bytes;
                for file in row.files.iter().flatten() { total=removal_archive_storage_sum_data(total,file.len)?; }
                check(self.owned_bytes()?.checked_add(row.name.capacity()).is_some_and(|n|n<=REMOVAL_ARCHIVE_TABLE),"removal-prior-memory")?;
                self.rows.push(row);self.storage_bytes=total;self.owned_bytes()?;Ok(())
            }
            pub(super) fn fresh(&self,request:&str,nonce:&str)->Result<()> {
                let request=archive_hex_data::<16>(request)?;
                check(worker::invocation_valid(nonce) && self.rows.iter().all(|row|
                    &row.name[8..]!=nonce && row.request!=Some(request)),"removal-prior-reused-request")
            }
        }
        fn removal_archive_storage_sum_data(before:u64,bytes:u64)->Result<u64> {
            before.checked_add(bytes).filter(|n|*n<=installation_record::PAYLOAD_LIMIT).ok_or("removal-prior-storage")
        }
        #[derive(Clone,Copy,PartialEq,Eq)]
        enum RemovalArchivePhase { FirstReading,FirstComplete,SecondReading,SecondComplete,Taken,PostReading,PostComplete,Refused }
        pub(super) struct RemovalArchiveScan {
            root:usize,phase:RemovalArchivePhase,first:Option<RemovalArchiveCensus>,current:Option<RemovalArchiveCensus>,
        }
        impl RemovalArchiveScan {
            fn first(root:usize)->Self { Self {root,phase:RemovalArchivePhase::FirstReading,first:None,current:None} }
            fn second(&mut self)->Result<()> {
                if self.phase!=RemovalArchivePhase::FirstComplete || self.first.is_some() || self.current.is_none() {
                    self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");
                }
                self.first=self.current.take();self.phase=RemovalArchivePhase::SecondReading;Ok(())
            }
            fn install(&mut self,value:RemovalArchiveCensus)->Result<()> {
                let result=(|| {
                    check(matches!(self.phase,RemovalArchivePhase::FirstReading|RemovalArchivePhase::SecondReading)
                        && self.current.is_none() && value.root==self.root,"removal-prior-stage")?;
                    let incoming=value.owned_bytes()?;
                    let retained=self.first.as_ref().map(RemovalArchiveCensus::owned_bytes).transpose()?.unwrap_or(0);
                    check(incoming.checked_add(retained).and_then(|n|n.checked_add(std::mem::size_of::<Self>()))
                        .is_some_and(|n|n<=2*REMOVAL_ARCHIVE_TABLE),"removal-prior-memory")?;
                    if self.phase==RemovalArchivePhase::SecondReading {
                        check(self.first.as_ref().is_some_and(|first|first==&value),"removal-prior-changed")?;
                    } Ok(())
                })();
                if let Err(why)=result {self.phase=RemovalArchivePhase::Refused;return Err(why);}
                self.current=Some(value);Ok(())
            }
            fn complete(&mut self)->Result<()> {
                if self.current.is_none() {self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");}
                self.phase=match self.phase { RemovalArchivePhase::FirstReading=>RemovalArchivePhase::FirstComplete,
                    RemovalArchivePhase::SecondReading=>RemovalArchivePhase::SecondComplete,_=>{
                        self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");} };
                Ok(())
            }
            fn begin_post(&mut self,root:usize,initial:bool)->Result<()> {
                let expected=if initial {RemovalArchivePhase::Taken}else{RemovalArchivePhase::PostComplete};
                if self.root!=root || self.phase!=expected {self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");}
                self.phase=RemovalArchivePhase::PostReading;Ok(())
            }
            fn complete_post(&mut self,result:Result<()>)->Result<()> {
                if let Err(why)=result {self.phase=RemovalArchivePhase::Refused;return Err(why);}
                if self.phase!=RemovalArchivePhase::PostReading {self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");}
                self.phase=RemovalArchivePhase::PostComplete;Ok(())
            }
            fn take(&mut self)->Result<RemovalArchiveCensus> {
                if self.phase!=RemovalArchivePhase::SecondComplete || self.first.is_none() || self.current.is_none() {
                    self.phase=RemovalArchivePhase::Refused;return Err("removal-prior-stage");
                }
                // The snapshot capture charges both tables while !complete.
                // Drop the first before moving the SAME second, once only.
                drop(self.first.take());self.phase=RemovalArchivePhase::Taken;
                self.current.take().ok_or("removal-prior-stage")
            }
        }
        fn archive_admission_chunk_data(expected:&[u8],offset:usize,bytes:&[u8])->bool {
            offset.checked_add(bytes.len()).filter(|end|*end<=expected.len())
                .is_some_and(|end|expected.get(offset..end)==Some(bytes))
        }
        fn archive_hex_data<const N:usize>(value:&str)->Result<[u8;N]> {
            check(value.len()==N*2 && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
                && value.bytes().any(|b|b!=b'0'),"removal-prior-hex")?;
            let mut out=[0;N];for (i,byte) in out.iter_mut().enumerate() {
                *byte=u8::from_str_radix(&value[i*2..i*2+2],16).map_err(|_|"removal-prior-hex")?;
            } Ok(out)
        }
        fn archive_directory_data(id:Identity,flags:u32,private:bool)->bool {
            id.ino!=0 && id.mode==(if private {0o040700}else{0o040755}) && id.uid==0 && id.gid==0
                && id.links>0 && id.size>=0 && flags==0
        }
        fn archive_file_data(id:Identity,flags:u32,slot:usize)->bool {
            slot<6 && id.ino!=0 && id.uid==0 && id.gid==0 && id.links==1 && flags==0
                && matches!(id.mode,0o100600|0o100444) && id.size>=0
                && (id.size as u64)<=(if slot==0 {REMOVAL_SNAPSHOT_LIMIT}else{mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64})
                && (id.mode==0o100600 || id.size>0)
        }
        fn archive_preadmission_shape_data(snapshot:Option<(u32,bool)>,admission:Option<u32>)->bool {
            match (snapshot,admission) {
                (None,None)=>true,(Some((0o100600,_)),None)=>true,
                (Some((0o100444,true)),None|Some(0o100600))=>true,_=>false,
            }
        }
        // Fixed linked-history comparison DATA. No shape, digest, index or
        // record returned here is a signature, EX, peer, or payload authority.
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) struct RemovalHistoryBindingData {
            target:mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData,
            source:[u8;20],digests:[[u8;32];5],
        }
        impl RemovalHistoryBindingData {
            fn from_record_binding(value:mobile_release_desktop::macos_remove_record::RemovalBindingData<'_>)->Result<Self> {
                Ok(Self {target:value.target,source:archive_hex_data(value.source_commit)?,digests:[
                    archive_hex_data(value.removal_descriptor_sha256)?,archive_hex_data(value.installed_producer_sha256)?,
                    archive_hex_data(value.installed_inventory_sha256)?,archive_hex_data(value.installation_state_sha256)?,
                    archive_hex_data(value.payload_roster_sha256)?]})
            }
            pub(super) fn target_data(&self)->mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData {self.target}
            pub(super) fn source_data(&self)->&[u8;20] {&self.source}
            pub(super) fn digests_data(&self)->&[[u8;32];5] {&self.digests}
            pub(super) fn matches_data(&self,value:mobile_release_desktop::macos_remove_record::RemovalBindingData<'_>)->bool {
                Self::from_record_binding(value).is_ok_and(|other|other==*self)
            }
            pub(super) fn with_binding<T>(&self,call:impl FnOnce(mobile_release_desktop::macos_remove_record::RemovalBindingData<'_>)->Result<T>)->Result<T> {
                let source=archive_hex_text_data(&self.source);let digests=self.digests.map(|sha|archive_hex_text_data(&sha));
                call(mobile_release_desktop::macos_remove_record::RemovalBindingData {target:self.target,source_commit:&source,
                    removal_descriptor_sha256:&digests[0],installed_producer_sha256:&digests[1],installed_inventory_sha256:&digests[2],
                    installation_state_sha256:&digests[3],payload_roster_sha256:&digests[4]})
            }
        }
        fn archive_hex_text_data(bytes:&[u8])->String {
            let mut out=String::with_capacity(bytes.len()*2);for byte in bytes {use std::fmt::Write;let _=write!(&mut out,"{byte:02x}");}out
        }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        struct RemovalPreviousData {request:[u8;16],nonce:[u8;16],tip:[u8;32]}
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) struct RemovalAttemptData {
            request:[u8;16],nonce:[u8;16],binding:RemovalHistoryBindingData,previous:Option<RemovalPreviousData>,
            tip:[u8;32],slot:usize,prefix:mobile_release_desktop::macos_remove_record::PrefixData,
            failure:Option<mobile_release_desktop::macos_remove_record::FirstFailureData>,genesis:Option<usize>,
        }
        impl RemovalAttemptData {
            fn from_record(value:&mobile_release_desktop::macos_remove_record::RemovalRecordData,slot:usize)->Result<Self> {
                check((1..6).contains(&slot),"removal-history-record-slot")?;
                let previous=value.previous_attempt_data().map(|(request,nonce,tip)|->Result<RemovalPreviousData>{Ok(RemovalPreviousData {
                    request:archive_hex_data(request)?,nonce:archive_hex_data(nonce)?,tip:archive_hex_data(tip)?})}).transpose()?;
                Ok(Self {request:archive_hex_data(value.request_id_data())?,nonce:archive_hex_data(value.root_nonce_data())?,
                    binding:RemovalHistoryBindingData::from_record_binding(value.binding_data())?,previous,
                    tip:archive_hex_data(value.digest_data())?,slot,prefix:value.prefix_data(),failure:value.first_failure_data(),genesis:None})
            }
            pub(super) fn request_id_data(&self)->&[u8;16] {&self.request}
            pub(super) fn root_nonce_data(&self)->&[u8;16] {&self.nonce}
            pub(super) fn binding_data(&self)->&RemovalHistoryBindingData {&self.binding}
            pub(super) fn raw_tip_sha256_data(&self)->&[u8;32] {&self.tip}
            pub(super) fn tip_slot_data(&self)->usize {self.slot}
            pub(super) fn prefix_data(&self)->mobile_release_desktop::macos_remove_record::PrefixData {self.prefix}
            pub(super) fn first_failure_data(&self)->Option<mobile_release_desktop::macos_remove_record::FirstFailureData> {self.failure}
            pub(super) fn previous_attempt_data(&self)->Option<(&[u8;16],&[u8;16],&[u8;32])> {
                self.previous.as_ref().map(|p|(&p.request,&p.nonce,&p.tip))
            }
        }
        #[derive(Clone,Copy,PartialEq,Eq)]
        struct RemovalGenesisSummaryData {request:[u8;16],nonce:[u8;16],binding:RemovalHistoryBindingData}
        fn removal_history_same_record_data(before:&mobile_release_desktop::macos_remove_record::RemovalRecordData,
            after:&mobile_release_desktop::macos_remove_record::RemovalRecordData)->Result<()> {
            check(before.request_id_data()==after.request_id_data() && before.root_nonce_data()==after.root_nonce_data()
                && before.previous_attempt_data()==after.previous_attempt_data()
                && RemovalHistoryBindingData::from_record_binding(before.binding_data())?
                    ==RemovalHistoryBindingData::from_record_binding(after.binding_data())?,"removal-history-record-binding")
        }
        fn removal_history_prefix_data(slot:usize)->Result<mobile_release_desktop::macos_remove_record::PrefixData> {
            use mobile_release_desktop::macos_remove_record::PrefixData as P;
            match slot {1=>Ok(P::AdmissionRecorded),2=>Ok(P::AppWithdrawn),3=>Ok(P::PayloadRosterRemoval),
                4=>Ok(P::PayloadAbsentObserved),_=>Err("removal-history-prefix-slot")}
        }
        const REMOVAL_FAILURE_KINDS:[mobile_release_desktop::macos_remove_record::FailureKindData;6]=[
            mobile_release_desktop::macos_remove_record::FailureKindData::OriginalFailed,
            mobile_release_desktop::macos_remove_record::FailureKindData::OriginalUnknown,
            mobile_release_desktop::macos_remove_record::FailureKindData::PostMismatch,
            mobile_release_desktop::macos_remove_record::FailureKindData::Deadline,
            mobile_release_desktop::macos_remove_record::FailureKindData::Persistence,
            mobile_release_desktop::macos_remove_record::FailureKindData::CloseUnknown];
        fn removal_history_writer_prefix_data(before:&mobile_release_desktop::macos_remove_record::RemovalRecordData,
            slot:usize,bytes:&[u8])->Result<()> {
            let binding=before.binding_data();
            if slot==5 {
                for kind in REMOVAL_FAILURE_KINDS {let next=before.first_failure_latched_data(kind,binding).map_err(|_|"removal-history-prefix")?;
                    if archive_admission_chunk_data(next.bytes_data(),0,bytes){return Ok(());}}
                Err("removal-history-prefix")
            }else{
                let next=before.next_prefix_data(removal_history_prefix_data(slot)?,binding).map_err(|_|"removal-history-prefix")?;
                check(archive_admission_chunk_data(next.bytes_data(),0,bytes),"removal-history-prefix")
            }
        }
        // Comparison-only template: canonical admission_data supplies all bytes
        // except the one SOURCE-fixed previousAttempt:null value. Only fixed
        // hex arrays from an already parsed tip supply that closed tuple. This
        // is never an encoder for publication; a writer must reread the actual
        // tip and call new_attempt_data. No historical raw hash is re-encoded.
        fn removal_linked_template_data(before:&RemovalAttemptData,nonce:&str,count:usize)->Result<Vec<u8>> {
            use mobile_release_desktop::macos_remove_record::RemovalRecordData;
            check(worker::invocation_valid(nonce) && (2..=64).contains(&count)
                && archive_hex_data::<16>(nonce)?!=before.nonce,"removal-history-prefix-bound")?;
            let dummy=if before.request==[0x11;16] {"22222222222222222222222222222222"}
                else {"11111111111111111111111111111111"};
            let made=before.binding.with_binding(|binding|RemovalRecordData::admission_data(dummy,nonce,binding)
                .map_err(|_|"removal-history-prefix-template"))?;
            let canonical=made.bytes_data();let key=b"\"previousAttempt\":null";
            let mut matches=canonical.windows(key.len()).enumerate().filter_map(|(at,part)|(part==key).then_some(at));
            let at=matches.next().ok_or("removal-history-prefix-template")?;
            check(matches.next().is_none(),"removal-history-prefix-template")?;
            let prior=format!("\"previousAttempt\":{{\"requestId\":\"{}\",\"rootNonce\":\"{}\",\"recordSha256\":\"{}\"}}",
                archive_hex_text_data(&before.request),archive_hex_text_data(&before.nonce),archive_hex_text_data(&before.tip));
            let length=canonical.len().checked_sub(key.len()).and_then(|n|n.checked_add(prior.len()))
                .filter(|n|*n<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT).ok_or("removal-history-prefix-template")?;
            let mut out=Vec::new();out.try_reserve_exact(length).map_err(|_|"removal-history-prefix-allocation")?;
            check(out.capacity()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT,"removal-history-prefix-memory")?;
            out.extend_from_slice(&canonical[..at]);out.extend_from_slice(prior.as_bytes());out.extend_from_slice(&canonical[at+key.len()..]);
            check(out.len()==length && made.owned_bytes_data().and_then(|n|n.checked_add(out.capacity()))
                .and_then(|n|n.checked_add(prior.capacity()+1024)).is_some_and(|n|n<=REMOVAL_ARCHIVE_PARSER),
                "removal-history-prefix-memory")?;
            Ok(out)
        }
        fn removal_linked_admission_prefix_data(before:&RemovalAttemptData,
            nonce:&str,count:usize,bytes:&[u8])->Result<Option<[u8;16]>> {
            check(bytes.len()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT,"removal-history-prefix-bound")?;
            let canonical=removal_linked_template_data(before,nonce,count)?;let key=b"\"requestId\":\"";
            // First occurrence is the fresh top-level field; the second is the
            // fixed previous tuple, which never varies. Exact codec-byte tests
            // below bind this SOURCE ordering rather than accepting JSON edits.
            let start=canonical.windows(key.len()).position(|w|w==key).ok_or("removal-history-prefix-template")?+key.len();
            check(bytes.len()<=canonical.len(),"removal-history-prefix-template")?;
            for (at,byte) in bytes.iter().enumerate(){
                if (start..start+32).contains(&at) {
                    check(byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),"removal-history-prefix-request")?;
                }else{check(Some(byte)==canonical.get(at),"removal-history-prefix")?;}
            }
            if bytes.len()<start+32 {return Ok(None);}
            let text=std::str::from_utf8(&bytes[start..start+32]).map_err(|_|"removal-history-prefix-request")?;
            let request=archive_hex_data::<16>(text)?;
            check(request!=before.request,"removal-history-prefix-request")?;
            // Revalidate the fully observed current identity through the SAME
            // admission codec. Historical binding remains comparison DATA.
            before.binding.with_binding(|binding| {
                let actual=mobile_release_desktop::macos_remove_record::RemovalRecordData::admission_data(text,nonce,binding)
                    .map_err(|_|"removal-history-prefix-request")?;
                removal_history_record_memory_data(Some(&actual),None,canonical.capacity()+bytes.len())
            })?;Ok(Some(request))
        }
        fn removal_history_record_memory_data(current:Option<&mobile_release_desktop::macos_remove_record::RemovalRecordData>,
            next:Option<&mobile_release_desktop::macos_remove_record::RemovalRecordData>,raw:usize)->Result<()> {
            let a=current.map(|r|r.owned_bytes_data().ok_or("removal-history-record-memory")).transpose()?.unwrap_or(0);
            let b=next.map(|r|r.owned_bytes_data().ok_or("removal-history-record-memory")).transpose()?.unwrap_or(0);
            // Fixed stream/serde/encoder/allocator temporary allowance plus all
            // retained raw capacities; reserved before the corresponding read.
            check(a.checked_add(b).and_then(|n|n.checked_add(raw)).and_then(|n|n.checked_add(256*1024))
                .is_some_and(|n|n<=REMOVAL_ARCHIVE_PARSER),"removal-history-record-memory")
        }
        fn removal_archive_record_data(slot:usize,mode:u32,bytes:&[u8],nonce:&str,
            snapshot:Option<(&ArchiveHeader,[u8;32])>,last:&mut Option<(mobile_release_desktop::macos_remove_record::RemovalRecordData,usize)>,
            request:&mut Option<[u8;16]>)->Result<()> {
            use mobile_release_desktop::macos_remove_record::RemovalRecordData;
            check((1..6).contains(&slot) && matches!(mode,0o100600|0o100444)
                && bytes.len()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT,"removal-history-record-shape")?;
            removal_history_record_memory_data(last.as_ref().map(|r|&r.0),None,bytes.len())?;
            if mode==0o100600 {
                if slot==1 {
                    check(last.is_none(),"removal-history-admission-order")?;
                    if let Some((header,sha))=snapshot {
                        let expected=header.admission(sha)?;
                        check(archive_admission_chunk_data(expected.bytes_data(),0,bytes),"removal-history-admission-prefix")?;
                    } // Snapshot-less linked prefixes are checked after all
                      // closed rows/real raw tip summaries have been collected.
                    return Ok(());
                }
                let old=&last.as_ref().ok_or("removal-history-progress-before-admission")?.0;
                return removal_history_writer_prefix_data(old,slot,bytes);
            }
            let parsed=RemovalRecordData::parse_shape_data(bytes).map_err(|_|"removal-history-record-parse")?;
            removal_history_record_memory_data(last.as_ref().map(|r|&r.0),Some(&parsed),bytes.len())?;
            check(parsed.root_nonce_data()==nonce,"removal-history-nonce-location")?;
            if slot==1 {
                check(last.is_none() && parsed.prefix_data()==removal_history_prefix_data(1)? && parsed.first_failure_data().is_none(),
                    "removal-history-admission-order")?;
                match snapshot {
                    Some((header,sha))=>{let genesis=header.summary(sha)?;
                        check(parsed.previous_attempt_data().is_none() && genesis.request==archive_hex_data(parsed.request_id_data())?
                            && genesis.nonce==archive_hex_data(nonce)?
                            && genesis.binding==RemovalHistoryBindingData::from_record_binding(parsed.binding_data())?,
                            "removal-history-genesis-binding")?;},
                    None=>check(parsed.previous_attempt_data().is_some(),"removal-history-genesis-missing")?,
                }
            }else{
                let old=&last.as_ref().ok_or("removal-history-progress-before-admission")?.0;
                removal_history_same_record_data(old,&parsed)?;
                check(old.first_failure_data().is_none(),"removal-history-after-failure")?;
                if slot==5 {
                    check(parsed.prefix_data()==old.prefix_data() && parsed.first_failure_data().is_some_and(|f|f.phase==old.prefix_data()),
                        "removal-history-failure-phase")?;
                }else{
                    check(old.prefix_data()==removal_history_prefix_data(slot-1)? && parsed.prefix_data()==removal_history_prefix_data(slot)?
                        && parsed.first_failure_data().is_none(),"removal-history-progress-order")?;
                }
            }
            *request=Some(archive_hex_data(parsed.request_id_data())?);*last=Some((parsed,slot));Ok(())
        }
        fn removal_archive_reference_shape_data(modes:[Option<u32>;6],app:bool)->bool {
            let snapshot=modes[0];let admission=modes[1];
            if modes.iter().flatten().any(|mode|!matches!(*mode,0o100600|0o100444)){return false;}
            if snapshot==Some(0o100600){return !app && modes[1..].iter().all(Option::is_none);}
            if admission.is_none(){return !app && modes[2..].iter().all(Option::is_none);}
            if admission==Some(0o100600){return !app && modes[2..].iter().all(Option::is_none);}
            if app && (snapshot!=Some(0o100444) || modes[4]==Some(0o100444)){return false;}
            let mut closed=true;
            for mode in &modes[2..5]{match mode{Some(0o100444) if closed=>{},Some(0o100600) if closed=>closed=false,
                None=>closed=false,_=>return false}}
            true
        }
        fn removal_archive_app_data(id:Identity,flags:u32)->bool {
            id.mode==0o040555 && id.uid==0 && id.gid==0 && id.ino!=0 && id.links>0 && id.size>=0 && flags==0
        }
        impl RemovalArchiveCensus {
            fn resolve_history_data(&mut self)->Result<()> {
                let count=self.rows.len();check(count<=64,"removal-history-count")?;
                let mut parents=[None;64];let mut children=[0u8;64];
                for index in 0..count {
                    if let Some(request)=self.rows[index].request {
                        check(self.rows[..index].iter().all(|old|old.request!=Some(request)),"removal-history-request-reuse")?;
                    }
                    let Some(node)=self.rows[index].attempt else {continue;};
                    check(node.nonce==archive_hex_data::<16>(&self.rows[index].name[8..])?,"removal-history-nonce-location")?;
                    if let Some(previous)=node.previous {
                        check(self.rows[index].snapshot.is_none() && self.rows[index].files[0].is_none()
                            && self.rows[index].app.is_none(),"removal-history-linked-shape")?;
                        let mut found=None;
                        for candidate in 0..count {
                            if let Some(old)=self.rows[candidate].attempt {
                                if old.request==previous.request && old.nonce==previous.nonce {
                                    check(found.is_none() && candidate!=index && old.tip==previous.tip && old.binding==node.binding,
                                        "removal-history-previous-tip")?;found=Some(candidate);
                                }
                            }
                        }
                        let parent=found.ok_or("removal-history-dangling")?;
                        children[parent]=children[parent].checked_add(1).ok_or("removal-history-fork")?;
                        check(children[parent]==1,"removal-history-fork")?;parents[index]=Some(parent);
                    }else{
                        let snapshot=self.rows[index].snapshot.ok_or("removal-history-genesis-missing")?;
                        check(snapshot.request==node.request && snapshot.nonce==node.nonce && snapshot.binding==node.binding
                            && self.rows[index].files[0].as_ref().is_some_and(|f|f.shape==RemovalArchiveShape::SealedBody),
                            "removal-history-genesis-binding")?;
                    }
                }
                for index in 0..count {
                    if self.rows[index].attempt.is_none(){continue;}
                    let mut at=index;let mut seen=0u64;
                    loop {check(at<count && seen&(1u64<<at)==0,"removal-history-cycle")?;seen|=1u64<<at;
                        match parents[at] {Some(parent)=>at=parent,None=>break}}
                    check(self.rows[at].snapshot.is_some(),"removal-history-genesis-missing")?;
                    self.rows[index].attempt.as_mut().ok_or("removal-history-node")?.genesis=Some(at);
                }
                self.owned_bytes()?;Ok(())
            }
            pub(super) fn genesis_index_data(&self,index:usize)->Option<usize> {
                self.rows.get(index)?.attempt.as_ref()?.genesis
            }
            pub(super) fn is_tip_data(&self,index:usize)->bool {
                let Some(Some(node))=self.rows.get(index).map(|row|row.attempt) else{return false;};
                node.genesis.is_some() && !self.rows.iter().filter_map(|row|row.attempt).any(|other|
                    other.previous.is_some_and(|p|p.request==node.request && p.nonce==node.nonce && p.tip==node.tip))
            }
            pub(super) fn has_admitted_history_data(&self)->bool {self.rows.iter().any(|row|row.attempt.is_some())}
        }
        // Semantic offsets describe bytes of ONE same original snapshot. They
        // are not paths to open, signature admission or payload permissions.
        pub(super) struct RemovalControlSpanData {
            kind:u8,path:String,identity:Identity,flags:u32,offset:u64,len:u64,digest:[u8;32],
        }
        impl RemovalControlSpanData {
            pub(super) fn kind_data(&self)->u8 {self.kind}
            pub(super) fn path_data(&self)->&str {&self.path}
            pub(super) fn identity_data(&self)->Identity {self.identity}
            pub(super) fn flags_data(&self)->u32 {self.flags}
            pub(super) fn offset_data(&self)->u64 {self.offset}
            pub(super) fn len_data(&self)->u64 {self.len}
            pub(super) fn digest_data(&self)->&[u8;32] {&self.digest}
        }
        struct RemovalSemanticSpans {selected:Vec<u8>,controls:Vec<RemovalControlSpanData>}
        impl RemovalSemanticSpans {
            fn new()->Self {Self {selected:Vec::new(),controls:Vec::new()}}
            fn memory(&self,extra:usize)->Result<usize> {
                let mut bytes=std::mem::size_of::<Self>().checked_add(self.selected.capacity())
                    .and_then(|n|n.checked_add(self.controls.capacity().checked_mul(std::mem::size_of::<RemovalControlSpanData>())?))
                    .and_then(|n|n.checked_add(extra)).ok_or("removal-history-span-memory")?;
                for row in &self.controls {bytes=bytes.checked_add(row.path.capacity()).ok_or("removal-history-span-memory")?;}
                check(bytes<=REMOVAL_HISTORY_SPANS,"removal-history-span-memory")?;Ok(bytes)
            }
            fn reserve(&mut self,count:usize)->Result<()> {
                check(count>0 && count<=SNAPSHOT_CONTROLS && self.controls.is_empty() && self.controls.capacity()==0,
                    "removal-history-span-count")?;
                self.memory(count.checked_mul(std::mem::size_of::<RemovalControlSpanData>()).ok_or("removal-history-span-memory")?)?;
                self.controls.try_reserve_exact(count).map_err(|_|"removal-history-span-allocation")?;self.memory(0)?;Ok(())
            }
            fn push(&mut self,row:RemovalControlSpanData)->Result<()> {
                check(self.controls.len()<self.controls.capacity(),"removal-history-span-count")?;
                self.memory(row.path.capacity())?;self.controls.push(row);self.memory(0)?;Ok(())
            }
        }
        pub(super) struct RemovalGenesisData {header:ArchiveHeader,spans:RemovalSemanticSpans,digest:[u8;32]}
        impl RemovalGenesisData {
            pub(super) fn request_id_data(&self)->&str {&self.header.values[0]}
            pub(super) fn root_nonce_data(&self)->&str {&self.header.values[1]}
            pub(super) fn binding_data(&self)->Result<RemovalHistoryBindingData> {Ok(self.header.summary(self.digest)?.binding)}
            pub(super) fn selected_bytes_data(&self)->&[u8] {&self.spans.selected}
            pub(super) fn controls_data(&self)->&[RemovalControlSpanData] {&self.spans.controls}
            pub(super) fn whole_sha256_data(&self)->&[u8;32] {&self.digest}
            pub(super) fn owned_bytes_data(&self)->Result<usize> {
                let extra=self.header.values.iter().try_fold(std::mem::size_of::<Self>(),|n,s|
                    n.checked_add(s.capacity()).ok_or("removal-history-span-memory"))?;
                // Includes inline storage conservatively twice rather than
                // taking a false credit for a move or an allocator capacity.
                self.spans.memory(extra)
            }
        }
        pub(super) fn parse_removal_genesis_data<F:FnMut(u64,&mut [u8])->Result<usize>>(size:u64,nonce:&str,read:F)
            ->Result<RemovalGenesisData> {
            let mut spans=RemovalSemanticSpans::new();
            let (complete,header,digest)=parse_removal_snapshot_with_spans_data(size,true,nonce,read,Some(&mut spans))?;
            check(complete,"removal-history-genesis-incomplete")?;
            let value=RemovalGenesisData {header:header.ok_or("removal-history-genesis-header")?,spans,digest};
            value.owned_bytes_data()?;Ok(value)
        }

        // Closed streaming DATA grammar: fixed SOURCE layout, never opens an
        // encoded path. It keeps one65KiB block, not a16MiB snapshot copy.
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        enum ArchiveParseError { Prefix,Refused(&'static str) }
        type ArchiveParse<T>=std::result::Result<T,ArchiveParseError>;
        impl From<&'static str> for ArchiveParseError { fn from(value:&'static str)->Self {Self::Refused(value)} }
        fn archive_require(ok:bool,why:&'static str)->ArchiveParse<()> {
            if ok {Ok(())} else {Err(ArchiveParseError::Refused(why))}
        }
        struct ArchiveCursor<F> {
            read:F,size:u64,loaded:u64,consumed:u64,block:[u8;65536],start:usize,end:usize,digest:Sha256,
        }
        impl<F:FnMut(u64,&mut [u8])->Result<usize>> ArchiveCursor<F> {
            fn new(size:u64,read:F)->Self {Self {read,size,loaded:0,consumed:0,block:[0;65536],start:0,end:0,digest:Sha256::new()}}
            fn fill(&mut self)->ArchiveParse<()> {
                if self.start<self.end {return Ok(());}
                if self.loaded==self.size {return Err(ArchiveParseError::Prefix);}
                let limit=usize::try_from((self.size-self.loaded).min(self.block.len() as u64)).map_err(|_|"removal-prior-size")?;
                let count=(self.read)(self.loaded,&mut self.block[..limit])?;
                archive_require(count>0 && count<=limit,"removal-prior-short-read")?;
                self.digest.update(&self.block[..count]);self.loaded+=count as u64;self.start=0;self.end=count;Ok(())
            }
            fn byte(&mut self)->ArchiveParse<u8> {
                self.fill()?;let value=self.block[self.start];self.start+=1;self.consumed+=1;Ok(value)
            }
            fn array<const N:usize>(&mut self)->ArchiveParse<[u8;N]> {
                let mut out=[0;N];for byte in &mut out {*byte=self.byte()?;}Ok(out)
            }
            fn u16(&mut self)->ArchiveParse<usize> {Ok(u16::from_be_bytes(self.array()?) as usize)}
            fn u32(&mut self)->ArchiveParse<u32> {Ok(u32::from_be_bytes(self.array()?))}
            fn u64(&mut self)->ArchiveParse<u64> {Ok(u64::from_be_bytes(self.array()?))}
            fn i64(&mut self)->ArchiveParse<i64> {Ok(i64::from_be_bytes(self.array()?))}
            fn string(&mut self,limit:usize,empty:bool,hex:bool)->ArchiveParse<String> {
                let count=self.u16()?;
                archive_require(count<=limit && (empty || count>0),"removal-prior-string-bound")?;
                let mut bytes=Vec::new();bytes.try_reserve_exact(count).map_err(|_|"removal-prior-allocation")?;
                for _ in 0..count {let byte=self.byte()?;
                    archive_require(if hex {byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)}else{byte.is_ascii_graphic() || byte==b' '},
                        "removal-prior-string")?;bytes.push(byte);}
                String::from_utf8(bytes).map_err(|_|ArchiveParseError::Refused("removal-prior-string"))
            }
            fn hex(&mut self,length:usize)->ArchiveParse<String> {
                archive_require(self.u16()?==length,"removal-prior-hex")?;
                let mut bytes=Vec::new();bytes.try_reserve_exact(length).map_err(|_|"removal-prior-allocation")?;
                for _ in 0..length {let byte=self.byte()?;
                    archive_require(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),"removal-prior-hex")?;bytes.push(byte);}
                archive_require(bytes.iter().any(|b|*b!=b'0'),"removal-prior-hex")?;
                String::from_utf8(bytes).map_err(|_|ArchiveParseError::Refused("removal-prior-hex"))
            }
            fn identity(&mut self,modes:&[u32])->ArchiveParse<(Identity,u32)> {
                let dev=self.i64()?;let ino=self.u64()?;archive_require(ino!=0,"removal-prior-identity")?;
                let mode=self.u32()?;archive_require(modes.contains(&mode),"removal-prior-identity")?;
                let uid=self.u32()?;archive_require(uid==0,"removal-prior-identity")?;
                let gid=self.u32()?;archive_require(gid==0,"removal-prior-identity")?;
                let flags=self.u32()?;archive_require(flags==0,"removal-prior-identity")?;
                let links=self.u64()?;archive_require(links>0 && (mode&0o170000!=0o100000 || links==1),"removal-prior-identity")?;
                let size=self.i64()?;archive_require(size>=0 && (mode!=0o100444 || size>0),"removal-prior-identity")?;
                let mtime=self.i64()?;let mtime_ns=self.i64()?;
                archive_require((0..1_000_000_000).contains(&mtime_ns),"removal-prior-identity")?;
                let ctime=self.i64()?;let ctime_ns=self.i64()?;
                archive_require((0..1_000_000_000).contains(&ctime_ns),"removal-prior-identity")?;
                Ok((Identity{dev,ino,mode,uid,gid,links,size,mtime,mtime_ns,ctime,ctime_ns},flags))
            }
            fn body(&mut self,length:u64,expected:[u8;32])->ArchiveParse<()> {
                archive_require(length>0 && length<=installation_record::INVENTORY_LIMIT as u64
                    && self.consumed.checked_add(length).is_some_and(|n|n<=REMOVAL_SNAPSHOT_LIMIT),"removal-prior-body-bound")?;
                let mut remaining=length;let mut digest=Sha256::new();
                while remaining>0 {self.fill()?;let take=(self.end-self.start).min(remaining as usize);
                    digest.update(&self.block[self.start..self.start+take]);self.start+=take;self.consumed+=take as u64;remaining-=take as u64;}
                archive_require(<[u8;32]>::from(digest.finalize())==expected,"removal-prior-body-hash")
            }
            fn eof(&mut self)->Result<[u8;32]> {
                check(self.consumed==self.size && self.loaded==self.size,"removal-prior-trailing")?;
                let mut extra=[0];check((self.read)(self.size,&mut extra)?==0,"removal-prior-eof")?;
                Ok(self.digest.clone().finalize().into())
            }
        }
        struct ArchiveHeader {
            target:mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData,
            values:[String;7],
        }
        impl ArchiveHeader {
            fn summary(&self,digest:[u8;32])->Result<RemovalGenesisSummaryData> {
                let record=self.admission(digest)?;
                Ok(RemovalGenesisSummaryData {request:archive_hex_data(record.request_id_data())?,
                    nonce:archive_hex_data(record.root_nonce_data())?,binding:RemovalHistoryBindingData::from_record_binding(record.binding_data())?})
            }
            fn admission(&self,snapshot_sha:[u8;32])->Result<mobile_release_desktop::macos_remove_record::RemovalRecordData> {
                use mobile_release_desktop::macos_remove_record::{RemovalBindingData,RemovalRecordData};
                let digest=snapshot_sha.iter().map(|b|format!("{b:02x}")).collect::<String>();
                RemovalRecordData::admission_data(&self.values[0],&self.values[1],RemovalBindingData {
                    target:self.target,source_commit:&self.values[2],installation_state_sha256:&self.values[3],
                    installed_producer_sha256:&self.values[4],installed_inventory_sha256:&self.values[5],
                    removal_descriptor_sha256:&self.values[6],payload_roster_sha256:&digest,
                }).map_err(|_|"removal-prior-admission-shape")
            }
        }
        fn archive_relative_path_data(value:&str,empty:bool)->bool {
            if value.is_empty(){return empty;}
            value.len()<=1024 && value.split('/').count()<=3 && value.split('/').all(component)
        }
        fn archive_control_path_data(kind:u8,path:&str)->bool {
            match kind {0=>archive_relative_path_data(path,false) && !path.starts_with('@')
                    && path!=paths::REGISTRATION_GATE_NAME && path!=paths::MAINTENANCE_GATE_NAME,1=>path=="@remove/producer.json",
                2=>path=="@remove/producer.sig",3=>path==paths::REGISTRATION_GATE_NAME,
                4=>path==paths::MAINTENANCE_GATE_NAME,_=>false}
        }
        fn archive_snapshot_grammar<F:FnMut(u64,&mut [u8])->Result<usize>>(cursor:&mut ArchiveCursor<F>,header:&mut Option<ArchiveHeader>,nonce:&str,
            mut spans:Option<&mut RemovalSemanticSpans>)->ArchiveParse<()> {
            for expected in REMOVAL_SNAPSHOT_MAGIC {archive_require(cursor.byte()?==*expected,"removal-prior-magic")?;}
            use mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData;
            let target=match cursor.byte()? {1=>MaintenanceTargetData::Arm64,2=>MaintenanceTargetData::Intel,
                _=>return Err(ArchiveParseError::Refused("removal-prior-target"))};
            let mut values:[String;7]=std::array::from_fn(|_|String::new());
            for (slot,length) in [32,32,40,64,64,64,64].into_iter().enumerate(){
                values[slot]=cursor.hex(length)?;
                if slot==1 {archive_require(values[slot]==nonce,"removal-prior-nonce-location")?;}
            }
            *header=Some(ArchiveHeader{target,values});
            let length=cursor.u32()? as usize;
            archive_require(length>0 && length<=mobile_release_desktop::macos_install_maintenance::INPUT_LIMIT,"removal-prior-selection-bound")?;
            let mut selection=Vec::new();selection.try_reserve_exact(length).map_err(|_|"removal-prior-allocation")?;
            for _ in 0..length {selection.push(cursor.byte()?);}
            // Target-specific closed release DATA. No source signer or current
            // authority is inferred from the old header or this parse.
            let selected=ReleaseSetData::parse_for_target_data(&selection,target).map_err(|_|"removal-prior-selection")?;
            drop(selected);
            if let Some(spans)=spans.as_deref_mut(){spans.memory(selection.capacity())?;spans.selected=selection;}else{drop(selection);}
            let directories=cursor.u16()?;archive_require((1..=SNAPSHOT_DIRECTORIES).contains(&directories),"removal-prior-directories")?;
            let mut previous:Option<String>=None;let mut total_children=0usize;
            let mut root_prior:Vec<(String,u64)>=Vec::new();
            root_prior.try_reserve_exact(REMOVAL_ARCHIVE_COUNT).map_err(|_|"removal-prior-allocation")?;
            for directory in 0..directories {
                let path=cursor.string(1024,true,false)?;
                archive_require(archive_relative_path_data(&path,true) && (directory!=0 || path.is_empty())
                    && previous.as_ref().is_none_or(|p|p<&path),"removal-prior-directory-order")?;
                let (identity,flags)=cursor.identity(&[0o040755,0o040700])?;
                archive_require(archive_directory_data(identity,flags,false) || archive_directory_data(identity,flags,true),"removal-prior-directory-identity")?;
                let count=cursor.u16()?;total_children=total_children.checked_add(count).ok_or("removal-prior-children")?;
                archive_require(total_children<=SNAPSHOT_CHILDREN && (!path.is_empty() || count<=350),"removal-prior-children")?;
                let mut last:Option<String>=None;
                for _ in 0..count {
                    let name=cursor.string(255,false,false)?;let inode=cursor.u64()?;
                    archive_require(removal_snapshot_child_data(path.is_empty(),&name,inode)
                        && last.as_ref().is_none_or(|old|old<&name),"removal-prior-child-order")?;
                    if path.is_empty() && name.starts_with(".remove-") {
                        archive_require(worker::removal_archive_name_data(&name) && root_prior.len()<REMOVAL_ARCHIVE_COUNT,"removal-prior-reference-name")?;
                        root_prior.push((name.clone(),inode));
                    }
                    last=Some(name);
                } previous=Some(path);
            }
            let prior=cursor.u16()?;archive_require(prior<=REMOVAL_ARCHIVE_COUNT && prior==root_prior.len(),"removal-prior-reference-count")?;
            let mut prior_bytes=0u64;
            for expected in &root_prior {
                let name=cursor.string(40,false,false)?;
                archive_require(worker::removal_archive_name_data(&name) && name==expected.0
                    && &name[8..]!=header.as_ref().ok_or("removal-prior-header")?.values[1].as_str(),"removal-prior-reference-order")?;
                let (identity,flags)=cursor.identity(&[0o040700])?;
                archive_require(archive_directory_data(identity,flags,true) && identity.ino==expected.1,"removal-prior-reference-identity")?;
                let mut modes=[None;6];
                for slot in 0..6 {
                    match cursor.byte()? {0=>{},1=>{
                        let (id,flags)=cursor.identity(&[0o100600,0o100444])?;
                        archive_require(archive_file_data(id,flags,slot),"removal-prior-reference-file")?;
                        let len=cursor.u64()?;archive_require(len==id.size as u64,"removal-prior-reference-file")?;
                        prior_bytes=removal_archive_storage_sum_data(prior_bytes,len)?;
                        let _digest=cursor.array::<32>()?;let tag=cursor.byte()?;
                        archive_require(tag==(if id.mode==0o100600 {1}else{2}),"removal-prior-reference-file")?;
                        modes[slot]=Some(id.mode);
                    },_=>return Err(ArchiveParseError::Refused("removal-prior-reference-tag"))}
                }
                let app=match cursor.byte()? {0=>false,1=>{let (id,flags)=cursor.identity(&[0o040555])?;
                    archive_require(removal_archive_app_data(id,flags),"removal-history-app-marker")?;true},
                    _=>return Err(ArchiveParseError::Refused("removal-history-app-marker"))};
                archive_require(removal_archive_reference_shape_data(modes,app),"removal-prior-reference-shape")?;
            }
            let controls=cursor.u16()?;archive_require(cursor.consumed<=SNAPSHOT_HEADER as u64,"removal-prior-header-bound")?;archive_require((1..=SNAPSHOT_CONTROLS).contains(&controls),"removal-prior-control-count")?;
            if let Some(spans)=spans.as_deref_mut(){spans.reserve(controls)?;}
            let mut last:Option<String>=None;
            for _ in 0..controls {
                let kind=cursor.byte()?;archive_require(kind<=4,"removal-prior-control-kind")?;
                let path=cursor.string(1024,false,false)?;
                archive_require(archive_control_path_data(kind,&path) && last.as_ref().is_none_or(|old|old<&path),"removal-prior-control-order")?;
                let (id,flags)=cursor.identity(&[0o100444])?;
                archive_require(id.size>0 && id.size as u64<=installation_record::INVENTORY_LIMIT as u64 && flags==0,"removal-prior-control-identity")?;
                let length=cursor.u64()?;archive_require(length==id.size as u64,"removal-prior-control-identity")?;
                let expected=cursor.array()?;
                let offset=cursor.consumed;cursor.body(length,expected)?;
                if let Some(spans)=spans.as_deref_mut(){spans.memory(path.len())?;spans.push(RemovalControlSpanData {kind,path:path.clone(),
                    identity:id,flags,offset,len:length,digest:expected})?;}
                last=Some(path);
            }
            Ok(())
        }
        fn parse_removal_snapshot_data<F:FnMut(u64,&mut [u8])->Result<usize>>(size:u64,sealed:bool,nonce:&str,read:F)
            ->Result<(bool,Option<ArchiveHeader>,[u8;32])> {
            parse_removal_snapshot_with_spans_data(size,sealed,nonce,read,None)
        }
        fn parse_removal_snapshot_with_spans_data<F:FnMut(u64,&mut [u8])->Result<usize>>(size:u64,sealed:bool,nonce:&str,read:F,
            spans:Option<&mut RemovalSemanticSpans>)->Result<(bool,Option<ArchiveHeader>,[u8;32])> {
            check(size<=REMOVAL_SNAPSHOT_LIMIT && (!sealed || size>0) && worker::invocation_valid(nonce),"removal-prior-snapshot-size")?;
            let mut cursor=ArchiveCursor::new(size,read);let mut header=None;
            let complete=match archive_snapshot_grammar(&mut cursor,&mut header,nonce,spans) {
                Ok(())=>true,Err(ArchiveParseError::Prefix) if !sealed=>false,
                Err(ArchiveParseError::Prefix)=>return Err("removal-prior-truncated-sealed"),
                Err(ArchiveParseError::Refused(why))=>return Err(why),
            };
            let digest=cursor.eof()?;Ok((complete,header,digest))
        }
        // All readers use the original Book. The boundary closes EVERY newly
        // adopted original even on partial open/read/POST failure, preserves the
        // first error, and never calls a consuming close twice on a live FD.
        fn removal_archive_scope<T>(book:&mut Install,call:impl FnOnce(&mut Install)->Result<T>)->Result<T> {
            let first=book.originals.len();let result=call(book);let mut failure=result.as_ref().err().copied();
            for index in (first..book.originals.len()).rev() {
                if book.originals[index].state==State::Owned {
                    if let Err(why)=book.check_name(index,true) {if failure.is_none(){failure=Some(why);}}
                }
                if !book.close(index) && failure.is_none(){failure=Some("removal-prior-close-unknown");}
            }
            if let Err(why)=book.clock(){if failure.is_none(){failure=Some(why);}}
            match failure {Some(why)=>Err(why),None=>result}
        }
        fn removal_archive_stat(book:&Install,index:usize,directory:bool,mode:u32)->Result<(Identity,u32)> {
            book.clock()?;book.check_name(index,true)?;book.protected(index,directory,Some(mode))?;book.clock()?;
            native::no_xattrs(book.fd(index)?.as_fd()).map_err(|_|"removal-prior-attributes")?;book.clock()?;
            let actual=stat::fstat(book.fd(index)?).map_err(|_|"removal-prior-stat")?;
            let original=&book.originals[index];
            let named=book.named(original.parent,&original.name).map_err(|_|"removal-prior-name")?;
            check(Identity::of(&actual)==book.identity(index)? && Identity::of(&named)==Identity::of(&actual)
                && actual.st_flags==0 && named.st_flags==0,"removal-prior-original")?;
            book.clock()?;Ok((Identity::of(&actual),actual.st_flags))
        }
        fn removal_archive_memory(book:&Install,extra:usize)->Result<()> {
            check(book.removal_snapshot_work_reserved && book.removal_control_reserved>=REMOVAL_SNAPSHOT_WORK,
                "removal-prior-unreserved")?;
            if let Some(capture)=&book.removal_snapshot_capture {capture.memory(extra)?;}
            else {check(extra.checked_add(2*REMOVAL_ARCHIVE_TABLE).is_some_and(|n|n<=REMOVAL_SNAPSHOT_WORK as usize),
                "removal-prior-memory")?;}
            Ok(())
        }
        // Fixed shallow census only, not the general Install roster. Vec
        // capacities are observable; no guessed private BTree-node allocation.
        fn removal_archive_roster_quote_data(private:bool,capacity:usize,names:usize,prospective:usize)->Result<usize> {
            check(capacity<=if private{7}else{350},"removal-prior-roster-bound")?;
            let total=std::mem::size_of::<Vec<(String,u64)>>().checked_add(capacity.checked_mul(std::mem::size_of::<(String,u64)>())
                .ok_or("removal-prior-roster-memory")?).and_then(|n|n.checked_add(names))
                .and_then(|n|n.checked_add(prospective)).and_then(|n|n.checked_add(65536+8192)).ok_or("removal-prior-roster-memory")?;
            check(total<=if private{128*1024}else{256*1024},"removal-prior-roster-memory")?;Ok(total)
        }
        fn removal_archive_inode(rows:&[(String,u64)],name:&str)->Option<u64> {
            rows.binary_search_by(|row|row.0.as_str().cmp(name)).ok().map(|at|rows[at].1)
        }
        fn removal_archive_roster(book:&mut Install,directory:usize,private:bool,limit:usize)->Result<Vec<(String,u64)>> {
            removal_archive_roster_quote_data(private,limit,0,0)?;
            removal_archive_memory(book,if private{128*1024}else{256*1024})?;
            let held=removal_archive_stat(book,directory,true,if private{0o700}else{0o755})?;
            let parent=book.originals[directory].parent;let name=book.originals[directory].name.clone();
            let result=removal_archive_scope(book,|book| {
                let reader=book.open(parent,&name,true)?;
                check(removal_archive_stat(book,reader,true,if private{0o700}else{0o755})?==held,"removal-prior-roster-original")?;
                let mut found:Vec<(String,u64)>=Vec::new();found.try_reserve_exact(limit).map_err(|_|"removal-prior-roster-allocation")?;
                check(found.capacity()<=limit,"removal-prior-roster-memory")?;
                removal_archive_roster_quote_data(private,found.capacity(),0,0)?;
                let mut names=0usize;let mut block=[0u8;65536];
                loop {
                    book.clock()?;let used=native::directory_block(book.fd(reader)?.as_fd(),&mut block).map_err(|_|"removal-prior-roster")?;
                    book.clock()?;check(used<=block.len(),"removal-prior-roster")?;if used==0{break;}
                    let mut offset=0;
                    while offset<used {
                        check(used-offset>=11,"removal-prior-directory-record")?;
                        let inode=u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_|"removal-prior-directory-record")?);
                        let kind=block[offset+8];let length=u16::from_ne_bytes([block[offset+9],block[offset+10]]) as usize;
                        let next=offset.checked_add(11+length).filter(|n|*n<=used).ok_or("removal-prior-directory-record")?;
                        let child=std::str::from_utf8(&block[offset+11..next]).map_err(|_|"removal-prior-directory-name")?;offset=next;
                        if child=="." || child==".." {continue;}
                        let root_alias=if !private && child==paths::APP_NAME {book.installed_root_roster_alias(reader)?}else{false};
                        check(installed_root_roster_child_data(child,root_alias) && inode!=0
                            && matches!(kind,nix::libc::DT_DIR|nix::libc::DT_REG) && found.len()<limit
                            && found.len()<found.capacity(),"removal-prior-roster-bound")?;
                        // Quote the largest allowed returned String capacity
                        // BEFORE allocation; then account its actual capacity.
                        removal_archive_roster_quote_data(private,found.capacity(),names,255)?;
                        let mut owned=String::new();owned.try_reserve_exact(child.len()).map_err(|_|"removal-prior-roster-allocation")?;
                        check(owned.capacity()<=255,"removal-prior-roster-memory")?;owned.push_str(child);
                        names=names.checked_add(owned.capacity()).ok_or("removal-prior-roster-memory")?;
                        removal_archive_roster_quote_data(private,found.capacity(),names,0)?;found.push((owned,inode));
                    }
                }
                // In-place sort has no sorting allocation. Strict order then
                // rejects duplicated actual records; lookup never hides one.
                found.sort_unstable_by(|a,b|a.0.cmp(&b.0));
                check(found.windows(2).all(|pair|pair[0].0<pair[1].0),"removal-prior-roster-duplicate")?;
                check(removal_archive_stat(book,reader,true,if private{0o700}else{0o755})?==held,"removal-prior-roster-post")?;
                Ok(found)
            });
            let post=removal_archive_stat(book,directory,true,if private{0o700}else{0o755});
            let result=result?;check(post?==held,"removal-prior-directory-post")?;Ok(result)
        }
        fn removal_archive_read_at(book:&Install,index:usize,offset:u64,bytes:&mut [u8])->Result<usize> {
            book.clock()?;let offset=i64::try_from(offset).map_err(|_|"removal-prior-read-offset")?;
            let actual=nix::sys::uio::pread(book.fd(index)?,bytes,offset).map_err(|_|"removal-prior-read")?;
            check(actual<=bytes.len(),"removal-prior-read-count")?;book.clock()?;Ok(actual)
        }
        fn removal_archive_raw_hash<F:FnMut(u64,&mut [u8])->Result<usize>>(size:u64,mut read:F)->Result<[u8;32]> {
            check(size<=REMOVAL_SNAPSHOT_LIMIT,"removal-prior-size")?;
            let mut block=[0;65536];let mut at=0;let mut digest=Sha256::new();
            while at<size {
                let limit=(size-at).min(block.len() as u64) as usize;let count=read(at,&mut block[..limit])?;
                check(count>0 && count<=limit,"removal-prior-short-read")?;digest.update(&block[..count]);at+=count as u64;
            }
            check(read(size,&mut block[..1])?==0,"removal-prior-eof")?;Ok(digest.finalize().into())
        }
        struct RemovalArchiveRead {
            file:RemovalArchiveFileReference,complete:bool,header:Option<ArchiveHeader>,raw:Option<Vec<u8>>,
        }
        fn removal_archive_file(book:&mut Install,directory:usize,slot:usize,inode:u64,budget_left:u64,nonce:&str)
            ->Result<RemovalArchiveRead> {
            check(slot<6,"removal-prior-slot")?;removal_archive_memory(book,REMOVAL_ARCHIVE_PARSER)?;
            removal_archive_scope(book,|book| {
                let index=book.open(Some(directory),REMOVAL_ARCHIVE_NAMES[slot],false)?;
                let id=book.identity(index)?;
                check(archive_file_data(id,0,slot) && id.ino==inode && id.dev==book.identity(directory)?.dev
                    && id.size as u64<=budget_left,"removal-prior-file-shape")?;
                let (identity,flags)=removal_archive_stat(book,index,false,id.mode&0o7777)?;
                let (complete,header,digest,raw)=if slot==0 {
                    let (complete,header,digest)=parse_removal_snapshot_data(id.size as u64,id.mode==0o100444,nonce,
                        |at,buf|removal_archive_read_at(book,index,at,buf))?;
                    (complete,header,digest,None)
                }else{
                    // Never retain a snapshot body. At most one <=16KiB record
                    // read joins its predecessor and the bounded codec scratch.
                    let size=usize::try_from(id.size).map_err(|_|"removal-history-record-bound")?;
                    check(size<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT,"removal-history-record-bound")?;
                    let mut raw=Vec::new();raw.try_reserve_exact(size).map_err(|_|"removal-history-record-allocation")?;
                    check(raw.capacity()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT,"removal-history-record-memory")?;
                    raw.resize(size,0);let mut at=0;
                    while at<size {let count=removal_archive_read_at(book,index,at as u64,&mut raw[at..])?;
                        check(count>0 && count<=size-at,"removal-prior-short-read")?;at+=count;}
                    let mut eof=[0];check(removal_archive_read_at(book,index,size as u64,&mut eof)?==0,"removal-prior-eof")?;
                    (false,None,Sha256::digest(&raw).into(),Some(raw))
                };
                check(removal_archive_stat(book,index,false,id.mode&0o7777)?==(identity,flags),"removal-prior-file-post")?;
                Ok(RemovalArchiveRead {file:RemovalArchiveFileReference {identity,flags,len:id.size as u64,digest,
                    shape:if id.mode==0o100444 {RemovalArchiveShape::SealedBody}else{RemovalArchiveShape::WritingPrefix}},complete,header,raw})
            })
        }
        fn removal_archive_app_stat(book:&Install,directory:usize,inode:u64)->Result<(Identity,u32)> {
            book.clock()?;let actual=book.named(Some(directory),"app").map_err(|_|"removal-history-app-name")?;
            let id=Identity::of(&actual);
            check(removal_archive_app_data(id,actual.st_flags) && id.ino==inode && id.dev==book.identity(directory)?.dev,
                "removal-history-app-shape")?;book.clock()?;Ok((id,actual.st_flags))
        }
        fn removal_archive_row(book:&mut Install,root:usize,name:&str,inode:u64,budget_left:u64)->Result<RemovalArchiveReference> {
            check(worker::removal_archive_name_data(name),"removal-prior-name")?;
            removal_archive_scope(book,|book| {
                let directory=book.open(Some(root),name,true)?;
                let (identity,flags)=removal_archive_stat(book,directory,true,0o700)?;
                check(archive_directory_data(identity,flags,true) && identity.ino==inode && identity.dev==book.identity(root)?.dev,
                    "removal-prior-directory")?;
                let roster=removal_archive_roster(book,directory,true,7)?;
                check(roster.iter().all(|(key,_)|key=="app" || REMOVAL_ARCHIVE_NAMES.contains(&key.as_str())),"removal-prior-children")?;
                let app=removal_archive_inode(&roster,"app").map(|inode|removal_archive_app_stat(book,directory,inode)).transpose()?;
                let mut files:[Option<RemovalArchiveFileReference>;6]=std::array::from_fn(|_|None);
                let mut header=None;let mut complete=false;let mut remaining=budget_left;let mut last=None;let mut request=None;
                for slot in 0..6 {
                    if let Some(inode)=removal_archive_inode(&roster,REMOVAL_ARCHIVE_NAMES[slot]) {
                        let read=removal_archive_file(book,directory,slot,inode,remaining,&name[8..])?;
                        remaining=remaining.checked_sub(read.file.len).ok_or("removal-prior-storage")?;
                        if slot==0 {
                            header=read.header;complete=read.complete;
                            if let Some(parsed)=&header {check(parsed.values[1]==name[8..],"removal-prior-nonce-location")?;
                                request=Some(archive_hex_data::<16>(&parsed.values[0])?);}
                        }else{
                            let snapshot=files[0].as_ref().filter(|f|f.shape==RemovalArchiveShape::SealedBody && complete)
                                .and_then(|f|header.as_ref().map(|h|(h,f.digest)));
                            let raw=read.raw.as_ref().ok_or("removal-history-record-missing")?;
                            removal_history_record_memory_data(last.as_ref().map(|r:&(mobile_release_desktop::macos_remove_record::RemovalRecordData,usize)|&r.0),
                                None,raw.capacity())?;
                            removal_archive_record_data(slot,read.file.identity.mode,raw,&name[8..],snapshot,&mut last,&mut request)?;
                        }
                        files[slot]=Some(read.file);
                    }
                }
                check(removal_archive_reference_shape_data(std::array::from_fn(|i|files[i].as_ref().map(|f|f.identity.mode)),app.is_some()),
                    "removal-prior-shape")?;
                let snapshot=if files[0].as_ref().is_some_and(|f|f.shape==RemovalArchiveShape::SealedBody) {
                    check(complete,"removal-history-genesis-incomplete")?;
                    Some(header.as_ref().ok_or("removal-prior-header")?.summary(files[0].as_ref().ok_or("removal-prior-header")?.digest)?)
                }else{None};
                let attempt=last.as_ref().map(|(record,slot)|RemovalAttemptData::from_record(record,*slot)).transpose()?;
                if let Some(before)=app {check(removal_archive_app_stat(book,directory,before.0.ino)?==before,"removal-history-app-post")?;}
                check(removal_archive_stat(book,directory,true,0o700)?==(identity,flags),"removal-prior-directory-post")?;
                Ok(RemovalArchiveReference {name:name.to_owned(),identity,flags,files,app,snapshot,attempt,request})
            })
        }
        fn removal_archive_original_quote_data(rows:usize,pending:usize)->Result<usize> {
            check(rows<=64 && pending<=rows,"removal-history-original-bound")?;
            rows.checked_mul(8).and_then(|n|n.checked_add(pending.checked_mul(2)?)).ok_or("removal-history-original-bound")
        }
        fn removal_archive_pending_admissions(book:&mut Install,table:&mut RemovalArchiveCensus)->Result<()> {
            let pending=table.rows.iter().filter(|row|row.files[0].is_none() && row.files[1].as_ref()
                .is_some_and(|file|file.shape==RemovalArchiveShape::WritingPrefix)).count();
            let additional=pending.checked_mul(2).ok_or("removal-history-original-bound")?;
            check(book.originals.len().checked_add(additional).is_some_and(|n|n<=24576),"removal-history-original-bound")?;
            for index in 0..table.rows.len() {
                let row=&table.rows[index];
                if row.files[0].is_some() || !row.files[1].as_ref().is_some_and(|file|file.shape==RemovalArchiveShape::WritingPrefix){continue;}
                let expected=row.files[1].as_ref().ok_or("removal-history-prefix-missing")?;
                let request=removal_archive_scope(book,|book| {
                    let directory=book.open(Some(table.root),row.name(),true)?;
                    check(removal_archive_stat(book,directory,true,0o700)?==(row.identity,row.flags),"removal-history-prefix-directory")?;
                    let read=removal_archive_file(book,directory,1,expected.identity.ino,expected.len,&row.name[8..])?;
                    check(read.file==*expected,"removal-history-prefix-original")?;
                    let raw=read.raw.as_ref().ok_or("removal-history-prefix-missing")?;
                    let mut any=false;let mut observed=None;
                    // Scalar/finite canonical comparisons only. One raw read,
                    // not64 rereads/parses; no inert prefix becomes a graph node.
                    for candidate in 0..table.rows.len() {
                        if !table.is_tip_data(candidate){continue;}
                        let before=table.rows[candidate].attempt.as_ref().ok_or("removal-history-node")?;
                        book.clock()?;
                        match removal_linked_admission_prefix_data(before,&row.name[8..],table.rows.len(),raw) {
                            Ok(request)=>{if let (Some(a),Some(b))=(observed,request){check(a==b,"removal-history-prefix-ambiguous")?;}
                                observed=observed.or(request);any=true;},
                            Err(why @ ("removal-history-prefix-allocation"|"removal-history-prefix-memory"|"removal-history-record-memory"))=>return Err(why),
                            Err(_)=>{},
                        }
                        book.clock()?;
                    }
                    check(any,"removal-history-prefix-unlinked")?;
                    check(removal_archive_stat(book,directory,true,0o700)?==(row.identity,row.flags),"removal-history-prefix-directory-post")?;
                    Ok(observed)
                })?;
                table.rows[index].request=request;
            }
            // Complete observed IDs may now expose reuse; this never promotes
            // any600 writer or changes a predecessor raw tip/phase.
            table.resolve_history_data()
        }
        fn begin_removal_archive_census(book:&mut Install,root:usize,second:bool)->Result<()> {
            book.clock()?;check(book.gate.parent==Some(root),"removal-prior-root-original")?;
            reserve_removal_snapshot_work(book)?;
            if second {let scan=book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?;
                check(scan.root==root,"removal-prior-root-original")?;scan.second()?;
            }else{check(book.removal_archive_scan.is_none(),"removal-prior-stage")?;
                book.removal_archive_scan=Some(RemovalArchiveScan::first(root));}
            Ok(())
        }
        fn complete_removal_archive_census(book:&mut Install)->Result<()> {
            book.clock()?;book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?.complete()
        }
        // Actual effectful read/close adapter, not a pure DATA constructor.
        // The caller separately holds its live-source or recovery-source and R/M
        // capability. No returned comparison row manufactures that authority.
        pub(super) fn read_removal_archive_census(book:&mut Install,root:usize,wanted:&BTreeSet<String>)->Result<RemovalArchiveCensus> {
            book.clock()?;check(book.gate.parent==Some(root) && wanted.len()<=286
                && wanted.iter().all(|name|!name.starts_with(".remove-")),"removal-prior-root-original")?;
            reserve_removal_snapshot_work(book)?;
            let actual=removal_archive_roster(book,root,false,350)?;
            check(wanted.iter().all(|name|removal_archive_inode(&actual,name).is_some()),"removal-prior-current-roster")?;
            let count=actual.iter().filter(|row|!wanted.contains(row.0.as_str())).count();
            let quote=removal_archive_original_quote_data(count,count)?;
            check(book.originals.len().checked_add(quote).is_some_and(|n|n<=24576),"removal-history-original-bound")?;
            let mut table=RemovalArchiveCensus::empty(root)?;
            for (name,inode) in &actual {
                if wanted.contains(name) {continue;}
                check(worker::removal_archive_name_data(name) && table.rows.len()<REMOVAL_ARCHIVE_COUNT,"removal-prior-foreign-or-bound")?;
                let row=removal_archive_row(book,root,name,*inode,installation_record::PAYLOAD_LIMIT-table.storage_bytes)?;table.add(row)?;
            }
            table.resolve_history_data()?;removal_archive_pending_admissions(book,&mut table)?;book.clock()?;Ok(table)
        }
        fn removal_archive_root_names(book:&mut Install,root:usize,wanted:&mut BTreeSet<String>)->Result<()> {
            let Some(scan)=book.removal_archive_scan.as_ref() else {return Ok(());};
            check(scan.root==root && scan.current.is_none() && matches!(scan.phase,
                RemovalArchivePhase::FirstReading|RemovalArchivePhase::SecondReading),"removal-prior-stage")?;
            let table=read_removal_archive_census(book,root,wanted)?;
            // Only successfully closed, independently checked rows can extend
            // this removal-only expected root; exact_roster still runs next.
            for row in table.rows(){check(wanted.insert(row.name.clone()),"removal-prior-name-collision")?;}
            book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?.install(table)
        }
        pub(super) fn removal_archive_storage_bytes(book:&Install)->Result<u64> {
            match &book.removal_archive_scan {None=>Ok(0),Some(scan)=>scan.current.as_ref()
                .map(RemovalArchiveCensus::storage_bytes).ok_or("removal-prior-stage")}
        }
        pub(super) fn take_removal_archive_census(book:&mut Install)->Result<RemovalArchiveCensus> {
            book.clock()?;book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?.take()
        }
        pub(super) fn removal_archive_fresh_request(book:&Install,request:&str,nonce:&str)->Result<()> {
            let scan=book.removal_archive_scan.as_ref().ok_or("removal-prior-stage")?;
            check(scan.phase==RemovalArchivePhase::FirstComplete,"removal-prior-stage")?;
            scan.current.as_ref().ok_or("removal-prior-stage")?.fresh(request,nonce)
        }
        // Actual fixed original POST; no recursive/parser/source authority and
        // no consuming/app-directory FD. Eight records per row at most.
        pub(super) fn post_removal_archive_references(book:&mut Install,census:&RemovalArchiveCensus)->Result<()> {
            book.clock()?;check(book.gate.parent==Some(census.root),"removal-prior-root-original")?;
            let quote=removal_archive_original_quote_data(census.rows().len(),0)?;
            check(book.originals.len().checked_add(quote).is_some_and(|n|n<=24576),"removal-history-original-bound")?;
            removal_archive_memory(book,128*1024)?;
            for row in census.rows() {
                removal_archive_scope(book,|book| {
                    let directory=book.open(Some(census.root),row.name(),true)?;
                    check(removal_archive_stat(book,directory,true,0o700)?==(row.identity,row.flags),"removal-prior-post-directory")?;
                    let roster=removal_archive_roster(book,directory,true,7)?;
                    check(roster.len()==row.files.iter().flatten().count()+usize::from(row.app.is_some()),"removal-prior-post-roster")?;
                    if let Some(app)=row.app {
                        check(removal_archive_inode(&roster,"app")==Some(app.0.ino) && removal_archive_app_stat(book,directory,app.0.ino)?==app,
                            "removal-history-app-post")?;
                    }
                    for (slot,file) in row.files.iter().enumerate() {
                        if let Some(file)=file {
                            check(removal_archive_inode(&roster,REMOVAL_ARCHIVE_NAMES[slot])==Some(file.identity.ino),"removal-prior-post-roster")?;
                            removal_archive_scope(book,|book| {
                                let index=book.open(Some(directory),REMOVAL_ARCHIVE_NAMES[slot],false)?;
                                check(removal_archive_stat(book,index,false,file.identity.mode&0o7777)?==(file.identity,file.flags),"removal-prior-post-file")?;
                                let digest=removal_archive_raw_hash(file.len,|at,buf|removal_archive_read_at(book,index,at,buf))?;
                                check(digest==file.digest && removal_archive_stat(book,index,false,file.identity.mode&0o7777)?==(file.identity,file.flags),
                                    "removal-prior-post-hash")?;Ok(())
                            })?;
                        }
                    }
                    if let Some(app)=row.app {check(removal_archive_app_stat(book,directory,app.0.ino)?==app,"removal-history-app-post")?;}
                    check(removal_archive_stat(book,directory,true,0o700)?==(row.identity,row.flags),"removal-prior-post-directory")?;Ok(())
                })?;
            }
            book.clock()
        }
        fn removal_archive_staged_post(book:&mut Install,census:&RemovalArchiveCensus,initial:bool)->Result<()> {
            book.clock()?;book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?.begin_post(census.root,initial)?;
            let result=post_removal_archive_references(book,census);
            book.removal_archive_scan.as_mut().ok_or("removal-prior-stage")?.complete_post(result)
        }
        pub(super) fn post_removal_archive_census(book:&mut Install,census:&RemovalArchiveCensus)->Result<()> {
            removal_archive_staged_post(book,census,true)
        }
        // The payload continuation already consumed the initial Taken POST.
        // Require its successful PostComplete, then perform fresh originals;
        // never reset Taken or skip checks after actual payload effects.
        pub(super) fn post_removal_archive_after_snapshot(book:&mut Install,census:&RemovalArchiveCensus)->Result<()> {
            removal_archive_staged_post(book,census,false)
        }
        // Fixed reinstall comparison DATA. None of these constructors reads a
        // directory, authenticates a signer, acquires R/M, or admits a move.
        // The new Install owner must supply those actual independent originals.
        pub(super) const REHOME_CHILD:&str="reinstall-v1";
        const REHOME_WORK:usize=256*1024;
        // State + versions + two producers per generation + three records per
        // invocation (no archived copy of current State) + one phase directory.
        const REHOME_TOP_LIMIT:usize=2+2*9+3*transaction::INVOCATION_LIMIT-1+transaction::INVOCATION_LIMIT;
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeKindData { Metadata,InstallPhases,RestorePhases,Versions }
        impl RehomeKindData {
            fn mode(self)->u32 {match self {Self::Metadata=>0o100444,Self::Versions=>0o040755,
                Self::InstallPhases|Self::RestorePhases=>0o040700}}
            fn phases(self)->&'static [&'static str] {match self {
                Self::InstallPhases=>&["staging-created.json","prepared.json","runtime-publication-confirmed.json","both-publications-confirmed.json"],
                Self::RestorePhases=>&["staging-created.json","prepared.json","app-publication-confirmed.json"],_=>&[]}}
        }
        pub(super) struct RehomeMoveData {name:String,kind:RehomeKindData}
        impl RehomeMoveData {
            pub(super) fn name_data(&self)->&str {&self.name}
            pub(super) fn kind_data(&self)->RehomeKindData {self.kind}
        }
        struct RehomeReleaseData {name:String,inventory:[u8;32]}
        pub(super) struct RehomeMoveSetData<'a> {
            genesis:&'a RemovalGenesisData,moves:Vec<RehomeMoveData>,releases:Vec<RehomeReleaseData>,files:usize,bytes:u64,
        }
        impl<'a> RehomeMoveSetData<'a> {
            fn memory(&self,extra:usize)->Result<usize> {
                let mut size=std::mem::size_of::<Self>().checked_add(self.moves.capacity()
                    .checked_mul(std::mem::size_of::<RehomeMoveData>()).ok_or("rehome-data-memory")?)
                    .and_then(|n|n.checked_add(self.releases.capacity().checked_mul(std::mem::size_of::<RehomeReleaseData>())?))
                    .and_then(|n|n.checked_add(extra)).ok_or("rehome-data-memory")?;
                for name in self.moves.iter().map(|x|&x.name).chain(self.releases.iter().map(|x|&x.name)) {
                    size=size.checked_add(name.capacity()).ok_or("rehome-data-memory")?;
                }
                check(size<=REHOME_WORK,"rehome-data-memory")?;Ok(size)
            }
            fn span(&self,path:&str)->Result<&RemovalControlSpanData> {
                self.genesis.controls_data().iter().find(|row|row.kind_data()==0 && row.path_data()==path)
                    .ok_or("rehome-data-missing-control")
            }
            fn metadata(&mut self,name:String,expected:Option<&str>)->Result<()> {
                let row=self.span(&name)?;
                if let Some(expected)=expected {check(*row.digest_data()==archive_hex_data::<32>(expected)?,"rehome-data-control-hash")?;}
                self.add(name,RehomeKindData::Metadata)
            }
            fn add(&mut self,name:String,kind:RehomeKindData)->Result<()> {
                check(component(&name) && name.len()<=255 && !self.moves.iter().any(|x|x.name==name)
                    && self.moves.len()<REHOME_TOP_LIMIT && self.moves.len()<self.moves.capacity(),"rehome-data-move-name")?;
                self.memory(name.capacity())?;self.moves.push(RehomeMoveData{name,kind});self.memory(0)?;Ok(())
            }
            fn add_generation(&mut self,selected:&ReleaseSetData,generation:GenerationData,current:bool)->Result<()> {
                let release=generation.release_data();let binding=release.binding_data();
                check(selected.contains_data(release) && component(binding.release) && self.releases.len()<9
                    && !self.releases.iter().any(|old|old.name==binding.release),"rehome-data-generation")?;
                // Source name constructors have <=255-byte components. Charge
                // both returned Strings and this bounded generation copy before
                // requesting either; recheck actual capacities before retention.
                self.memory(4096+2*255+binding.release.len())?;
                let pair=control_names(selected,binding.release)?;
                let genesis=self.genesis;
                let current_digest=if current {Some(genesis.header.values[4].as_str())}else{None};
                self.metadata(pair.0,current_digest)?;self.metadata(pair.1,None)?;
                let name=binding.release.to_owned();self.memory(name.capacity())?;
                self.releases.push(RehomeReleaseData{name,inventory:archive_hex_data(binding.inventory_sha256)?});self.memory(0)?;Ok(())
            }
            // Names originate only in these existing SOURCE constructors and
            // parsed State evidence. Encoded snapshot paths are compared, never
            // used to select an extra root leaf or an arbitrary destination.
            pub(super) fn from_genesis_data(genesis:&'a RemovalGenesisData,selected:&ReleaseSetData,
                state:&StateData,intents:&[&IntentData])->Result<Self> {
                check(state.mutation_recorded_data() && state.current_data().release_data()==selected.current_data()
                    && intents.len()==state.evidence_data().count()+1 && !intents.is_empty()
                    && intents.len()<=transaction::INVOCATION_LIMIT,"rehome-data-history")?;
                let selected_raw=data_selection_bytes(selected)?;
                check(selected_raw==genesis.selected_bytes_data() && selected.target_data()==genesis.header.target
                    && archive_hex_data::<32>(state.digest_data())?==archive_hex_data::<32>(&genesis.header.values[3])?,"rehome-data-genesis")?;
                let mut moves=Vec::new();let mut releases=Vec::new();
                let initial=std::mem::size_of::<Self>()+REHOME_TOP_LIMIT*std::mem::size_of::<RehomeMoveData>()
                    +9*std::mem::size_of::<RehomeReleaseData>()+selected_raw.capacity()+4096;
                check(initial<=REHOME_WORK,"rehome-data-memory")?;
                moves.try_reserve_exact(REHOME_TOP_LIMIT).map_err(|_|"rehome-data-allocation")?;
                releases.try_reserve_exact(9).map_err(|_|"rehome-data-allocation")?;
                let mut value=Self{genesis,moves,releases,files:0,bytes:0};value.memory(selected_raw.capacity()+4096)?;
                drop(selected_raw);
                value.metadata(transaction::STATE_NAME.to_owned(),Some(state.digest_data()))?;
                value.add("versions".to_owned(),RehomeKindData::Versions)?;
                value.add_generation(selected,state.current_data(),true)?;
                for generation in state.retained_data() {value.add_generation(selected,generation,false)?;}
                for (index,intent) in intents.iter().enumerate() {
                    let id=intent.invocation_data();
                    check(worker::invocation_valid(id) && !intents[..index].iter().any(|old|old.invocation_data()==id)
                        && selected.contains_data(intent.next_data()),"rehome-data-invocation")?;
                    let evidence=state.evidence_data().find(|old|old.invocation==id);
                    check((id==state.invocation_data())!=evidence.is_some(),"rehome-data-invocation")?;
                    if let Some(evidence)=evidence {check(evidence.intent_sha256==intent.digest_data(),"rehome-data-history-hash")?;}
                    else {check(intent.action_data()==state.action_data() && intent.request_id_data()==state.request_id_data()
                        && intent.next_data()==state.current_data().release_data(),"rehome-data-current-intent")?;}
                    value.memory(4096+3*255)?;
                    value.metadata(data(transaction::intent_name_data(id))?,Some(intent.digest_data()))?;
                    value.metadata(data(transaction::capsule_name_data(id))?,evidence.map(|old|old.capsule_sha256))?;
                    if let Some(evidence)=evidence {
                        value.metadata(data(transaction::archived_state_name_data(id))?,Some(evidence.state_sha256))?;
                    }
                    match intent.action_data() {
                        ActionData::SamePackageNoop=>{},
                        ActionData::RestoreFixedApp=>value.add(format!(".install-{id}"),RehomeKindData::RestorePhases)?,
                        ActionData::FreshInstall|ActionData::Update=>value.add(format!(".install-{id}"),RehomeKindData::InstallPhases)?,
                        ActionData::Uninstall=>return Err("rehome-data-install-action"),
                    }
                }
                value.moves.sort_unstable_by(|a,b| {
                    (a.kind==RehomeKindData::Versions).cmp(&(b.kind==RehomeKindData::Versions)).then(a.name.cmp(&b.name))
                });
                let expected=value.moves.iter().map(|row|if row.kind==RehomeKindData::Metadata{1}else{row.kind.phases().len()})
                    .sum::<usize>().checked_add(value.releases.len()*2).ok_or("rehome-data-control-count")?;
                let mut special=[false;5];
                for row in genesis.controls_data() {
                    if row.kind_data()!=0 {
                        let kind=row.kind_data() as usize;
                        check((1..=4).contains(&kind) && !special[kind],"rehome-data-source-controls")?;special[kind]=true;continue;
                    }
                    check(value.selects_control_data(row),"rehome-data-foreign-control")?;
                    value.files=value.files.checked_add(1).ok_or("rehome-data-control-count")?;
                    value.bytes=removal_archive_storage_sum_data(value.bytes,row.len_data())?;
                }
                check(value.files==expected && value.files<=SNAPSHOT_CONTROLS-4 && special[1..].iter().all(|x|*x)
                    && value.directories_data()<=SNAPSHOT_DIRECTORIES,"rehome-data-complete-controls")?;
                value.memory(0)?;Ok(value)
            }
            fn selects_control_data(&self,row:&RemovalControlSpanData)->bool {
                let path=row.path_data();
                if row.kind_data()!=0 || row.identity_data().mode!=0o100444 || row.flags_data()!=0
                    || row.identity_data().links!=1 || row.len_data()==0 {return false;}
                let mut parts=path.split('/');let Some(top)=parts.next()else{return false;};
                let Some(spec)=self.moves.iter().find(|x|x.name==top)else{return false;};
                match spec.kind {
                    RehomeKindData::Metadata=>parts.next().is_none(),
                    RehomeKindData::InstallPhases|RehomeKindData::RestorePhases=>parts.next()
                        .is_some_and(|leaf|spec.kind.phases().contains(&leaf)) && parts.next().is_none(),
                    RehomeKindData::Versions=>{
                        let Some(release)=parts.next().and_then(|name|self.releases.iter().find(|r|r.name==name))else{return false;};
                        let permitted=match parts.next(){Some(installation_record::INVENTORY_NAME)=>*row.digest_data()==release.inventory,
                            Some(installation_record::RECORD_NAME)=>true,_=>false};permitted && parts.next().is_none()
                    },
                }
            }
            pub(super) fn moves_data(&self)->&[RehomeMoveData] {&self.moves}
            pub(super) fn files_data(&self)->usize {self.files}
            pub(super) fn bytes_data(&self)->u64 {self.bytes}
            pub(super) fn directories_data(&self)->usize {1+self.releases.len()+self.moves.iter().filter(|x|x.kind!=RehomeKindData::Metadata).count()}
            pub(super) fn owned_bytes_data(&self)->Result<usize> {self.memory(0)}
            pub(super) fn prefix_data(&self,sides:&[RehomeSideData])->Result<usize> {
                rehome_prefix_data(self.moves.len(),sides)
            }
            pub(super) fn state_position_data(&self)->Result<usize> {
                self.moves.iter().position(|x|x.name==transaction::STATE_NAME).ok_or("rehome-data-state-missing")
            }
            fn prefix_counts(&self,prefix:usize)->Result<(usize,usize,u64)> {
                check(prefix<=self.moves.len(),"rehome-data-prefix-count")?;
                let mut directories=1usize;let mut files=0usize;let mut bytes=0u64;
                for spec in &self.moves[..prefix] {
                    directories=directories.checked_add(match spec.kind {RehomeKindData::Metadata=>0,
                        RehomeKindData::Versions=>1+self.releases.len(),_=>1}).ok_or("rehome-data-audit-count")?;
                    for row in self.genesis.controls_data().iter().filter(|row|row.kind_data()==0) {
                        if row.path_data().split('/').next()==Some(spec.name.as_str()) {
                            files=files.checked_add(1).ok_or("rehome-data-audit-count")?;
                            bytes=removal_archive_storage_sum_data(bytes,row.len_data())?;
                        }
                    }
                }Ok((directories,files,bytes))
            }
        }
        fn data_selection_bytes(selected:&ReleaseSetData)->Result<Vec<u8>> {
            selected.encode_data().map_err(|_|"rehome-data-selection")
        }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeSideData { OldOnly,NewOnly,Both,Neither,Unknown }
        fn rehome_prefix_data(total:usize,sides:&[RehomeSideData])->Result<usize> {
            check(total>0 && total<=REHOME_TOP_LIMIT && sides.len()==total,"rehome-data-prefix-count")?;
            let mut prefix=0;let mut old=false;
            for side in sides {match side {
                RehomeSideData::NewOnly if !old=>prefix+=1,RehomeSideData::OldOnly=>old=true,
                _=>return Err("rehome-data-prefix-shape"),
            }}Ok(prefix)
        }
        // These labels are a future current observer's comparison DATA, not
        // proof that a filename is old, that State is signed, or that EX exists.
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeStateData { Absent,ExactOld,RecordedNew,PartialNew,Foreign,Unknown }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeFreshData { Absent,RecordedNew,PartialNew,Foreign,Unknown }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeVersionsData { ExactOld,Absent,DistinctFreshEmpty,RecordedNew,PartialNew,Foreign,Unknown }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        pub(super) enum RehomeBoundaryData { ContinueOldPrefix,FreshPreparation,ObserveNewInstallation,PreservePartialNew,Refused }
        pub(super) fn rehome_boundary_data(total:usize,prefix:usize,state_position:usize,state:RehomeStateData,
            versions:RehomeVersionsData,evidence:RehomeFreshData,payload:RehomeFreshData)->RehomeBoundaryData {
            use RehomeBoundaryData as B;
            if total==0 || total>REHOME_TOP_LIMIT || prefix>total || state_position>=total
                || matches!(state,RehomeStateData::Unknown|RehomeStateData::Foreign)
                || matches!(versions,RehomeVersionsData::Unknown|RehomeVersionsData::Foreign)
                || matches!(evidence,RehomeFreshData::Unknown|RehomeFreshData::Foreign)
                || matches!(payload,RehomeFreshData::Unknown|RehomeFreshData::Foreign) {return B::Refused;}
            if prefix<total {
                return if versions==RehomeVersionsData::ExactOld && evidence==RehomeFreshData::Absent
                    && payload==RehomeFreshData::Absent && state==(if state_position<prefix {RehomeStateData::Absent}else{RehomeStateData::ExactOld})
                    {B::ContinueOldPrefix}else{B::Refused};
            }
            if state==RehomeStateData::Absent && evidence==RehomeFreshData::Absent && payload==RehomeFreshData::Absent
                && matches!(versions,RehomeVersionsData::Absent|RehomeVersionsData::DistinctFreshEmpty) {return B::FreshPreparation;}
            if state==RehomeStateData::RecordedNew && versions==RehomeVersionsData::RecordedNew
                && evidence==RehomeFreshData::RecordedNew && payload==RehomeFreshData::RecordedNew {return B::ObserveNewInstallation;}
            if state==RehomeStateData::ExactOld || versions==RehomeVersionsData::ExactOld {return B::Refused;}
            // No mutation authorization from this result. Preserve the exact
            // partial/foreign new cut; a separately reviewed recovery is needed.
            B::PreservePartialNew
        }
        pub(super) fn rehome_rebind_data(kind:RehomeKindData,before:Identity,before_flags:u32,
            actual:Identity,actual_flags:u32,named:Identity,named_flags:u32)->bool {
            before.ino!=0 && before.uid==0 && before.gid==0 && before.mode==kind.mode()
                && before.links>0 && (kind!=RehomeKindData::Metadata || before.links==1 && before.size>0)
                && before.size>=0 && before_flags==0 && actual_flags==0 && named_flags==0 && actual==named
                && (0..1_000_000_000).contains(&actual.ctime_ns)
                && (Identity {ctime:actual.ctime,ctime_ns:actual.ctime_ns,..before})==actual
        }
        pub(super) fn rehome_fresh_versions_data(archived:Identity,current:Identity,flags:u32,children:usize)->bool {
            archive_directory_data(archived,0,false) && archive_directory_data(current,flags,false)
                && archived.dev==current.dev && archived.ino!=current.ino && children==0
        }
        // Actual callers must record ReturnedData BEFORE any clock, named POST,
        // sync or close. A newly observed prefix supplies no earlier return.
        pub(super) struct RehomeProgressData {total:usize,next:usize,pending:bool,returned:Option<ReturnedData>,first:Option<&'static str>}
        impl RehomeProgressData {
            pub(super) fn from_observation_data(total:usize,sides:&[RehomeSideData])->Result<Self> {
                Ok(Self{total,next:rehome_prefix_data(total,sides)?,pending:false,returned:None,first:None})
            }
            pub(super) fn begin_data(&mut self,index:usize)->Result<()> {
                if self.first.is_some() || self.pending || index!=self.next || index>=self.total {
                    return Err(*self.first.get_or_insert("rehome-data-effect-order"));
                }
                self.pending=true;self.returned=None;Ok(())
            }
            pub(super) fn returned_data(&mut self,value:ReturnedData)->Result<()> {
                if !self.pending || self.returned.is_some() {return Err(*self.first.get_or_insert("rehome-data-effect-order"));}
                self.returned=Some(value);if value!=ReturnedData::KnownSuccess {self.first.get_or_insert("rehome-original-not-successful");}Ok(())
            }
            pub(super) fn post_data(&mut self,result:Result<()>)->Result<()> {
                if let Err(why)=result {self.first.get_or_insert(why);}
                if !self.pending || self.returned!=Some(ReturnedData::KnownSuccess) {self.first.get_or_insert("rehome-original-not-successful");}
                if let Some(why)=self.first {return Err(why);}
                self.pending=false;self.next+=1;Ok(())
            }
            pub(super) fn observed_prefix_data(&self)->usize {self.next}
            pub(super) fn last_return_data(&self)->Option<ReturnedData> {self.returned}
            pub(super) fn first_failure_data(&self)->Option<&'static str> {self.first}
        }
        // Proposed typed optional-child value. This is comparison DATA produced
        // only AFTER the future caller's complete nested audit; it does not add
        // a census name allowance or trust a caller's claimed hash/counts.
        #[derive(PartialEq,Eq)]
        pub(super) struct RehomeReferenceData {
            root:Identity,flags:u32,prefix:usize,total:usize,directories:usize,files:usize,bytes:u64,digest:[u8;32],
        }
        impl RehomeReferenceData {
            pub(super) fn observed_data(plan:&RehomeMoveSetData<'_>,root:Identity,flags:u32,prefix:usize,
                directories:usize,files:usize,bytes:u64,digest:[u8;32])->Result<Self> {
                check(archive_directory_data(root,flags,true) && digest.iter().any(|byte|*byte!=0)
                    && plan.prefix_counts(prefix)?==(directories,files,bytes),"rehome-data-child-reference")?;
                Ok(Self{root,flags,prefix,total:plan.moves.len(),directories,files,bytes,digest})
            }
            pub(super) fn matches_data(&self,other:&Self)->bool {self==other}
            pub(super) fn complete_data(&self)->bool {self.prefix==self.total}
            pub(super) fn storage_bytes_data(&self)->u64 {self.bytes}
        }
        // Exact primitive-count quote for ONE proposed complete nested audit:
        // one original plus one distinct roster reader per directory, one
        // sequential original per file. NOT the live authority to start it.
        // Outer six-slot8P work is separate and cannot replace this addition.
        pub(super) fn rehome_audit_quote_data(directories:usize,files:usize,passes:usize,
            existing_records:usize,existing_live:usize,retained_work:usize,plan_work:usize,
            other_storage:u64,control_storage:u64)->Result<usize> {
            check((1..=SNAPSHOT_DIRECTORIES).contains(&directories) && files<=SNAPSHOT_CONTROLS-4 && passes>0,
                "rehome-data-audit-count")?;
            let records=directories.checked_mul(2).and_then(|n|n.checked_add(files)).and_then(|n|n.checked_mul(passes))
                .and_then(|n|n.checked_add(existing_records)).ok_or("rehome-data-audit-budget")?;
            check(records<=24576 && existing_live.checked_add(5).is_some_and(|n|n<=96)
                && plan_work<=REHOME_WORK && retained_work.checked_add(plan_work)
                    .and_then(|n|n.checked_add(65536+8192)).is_some_and(|n|n<=REMOVAL_SNAPSHOT_WORK as usize)
                && other_storage.checked_add(control_storage).is_some_and(|n|n<=installation_record::PAYLOAD_LIMIT),
                "rehome-data-audit-budget")?;Ok(records)
        }

        #[cfg(test)]
        fn rehome_test_fixture()->(RemovalGenesisData,ReleaseSetData,StateData,IntentData) {
            use mobile_release_desktop::macos_remove_protocol::{BindingData,BindingInputData,TargetData};
            let (seed,_)=removal_archive_test_snapshot(false,0);
            let seed=parse_removal_genesis_data(seed.len() as u64,&"2".repeat(32),|at,out|{
                let at=at as usize;let count=out.len().min(seed.len()-at);out[..count].copy_from_slice(&seed[at..at+count]);Ok(count)
            }).unwrap();
            let inventory=b"inert public inventory DATA";let producer=b"inert installed producer DATA";
            let remover=b"inert remove producer DATA";let signature=b"inert signature DATA, NOT verified";
            let inventory_sha=hash(inventory);let producer_sha=hash(producer);let remover_sha=hash(remover);
            let mut selection:serde_json::Value=serde_json::from_slice(seed.selected_bytes_data()).unwrap();
            selection["current"]["inventorySha256"]=serde_json::json!(inventory_sha);
            let selected_raw=serde_json::to_vec(&selection).unwrap();
            let selected=ReleaseSetData::parse_for_target_data(&selected_raw,
                mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64).unwrap();
            let selected_raw=selected.encode_data().unwrap();
            let invocation="b".repeat(32);let intent_raw=IntentData::encode_data(&invocation,&"c".repeat(32),
                ActionData::FreshInstall,None,&selected).unwrap();
            let intent=IntentData::parse_data(&intent_raw,&selected).unwrap();
            let generation=GenerationData::from_original_fields_data(&selected,selected.current_data(),&"d".repeat(32),
                installation_record::DirectoryIdentity{device:1,inode:90,mode:0o040755,uid:0,gid:0,flags:0},
                AppIdentityData::from_original_fields_data(1,91,0o040555,0,0,0).unwrap()).unwrap();
            let state_raw=StateData::encode_applied_data(&intent,None,&generation,&selected).unwrap();
            let state=StateData::parse_data(&state_raw,&selected).unwrap();
            let release=selected.current_data().binding_data().release;let pair=control_names(&selected,release).unwrap();
            let mut bodies:Vec<(String,u8,Vec<u8>)>=vec![
                (transaction::STATE_NAME.into(),0,state_raw),
                (pair.0,0,producer.to_vec()),(pair.1,0,signature.to_vec()),
                (format!("versions/{release}/{}",installation_record::INVENTORY_NAME),0,inventory.to_vec()),
                (format!("versions/{release}/{}",installation_record::RECORD_NAME),0,b"inert record DATA".to_vec()),
                (transaction::intent_name_data(&invocation).unwrap(),0,intent_raw),
                (transaction::capsule_name_data(&invocation).unwrap(),0,b"inert capsule DATA, NOT original settlement".to_vec()),
                ("@remove/producer.json".into(),1,remover.to_vec()),("@remove/producer.sig".into(),2,signature.to_vec()),
                (paths::REGISTRATION_GATE_NAME.into(),3,paths::REGISTRATION_GATE_BYTES.to_vec()),
                (paths::MAINTENANCE_GATE_NAME.into(),4,paths::MAINTENANCE_GATE_BYTES.to_vec()),
            ];
            for phase in RehomeKindData::InstallPhases.phases() {
                bodies.push((format!(".install-{invocation}/{phase}"),0,b"inert phase DATA".to_vec()));
            }
            bodies.sort_unstable_by(|a,b|a.0.cmp(&b.0));
            let identity=Identity{dev:1,ino:40,mode:0o040755,uid:0,gid:0,links:2,size:64,
                mtime:1,mtime_ns:0,ctime:1,ctime_ns:0};
            let controls=bodies.iter().enumerate().map(|(index,(path,kind,raw))|RemovalSnapshotControl{
                path:path.clone(),identity:Identity{ino:100+index as u64,mode:0o100444,links:1,size:raw.len() as i64,..identity},
                flags:0,size:raw.len() as u64,digest:Sha256::digest(raw).into(),kind:*kind,held:None}).collect();
            // Real fixed snapshot encoder and sole parser, but inert unsigned
            // bodies/identities. No test claims signature or filesystem proof.
            let mut capture=RemovalSnapshotCapture{root:0,versions:None,prior_archives:None,controls,
                directories:vec![RemovalSnapshotDirectory{path:String::new(),identity,flags:0,children:vec![]}],
                complete:false,quote:Some((0,0)),failed:false};
            capture.finish(RemovalArchiveCensus::empty(0).unwrap()).unwrap();
            let binding=selected.current_data().binding_data();
            let request=BindingData::new_data(BindingInputData{request_id:&"1".repeat(32),root_nonce:&"2".repeat(32),
                source_commit:binding.source_commit,release,target:TargetData::Arm64,remove_producer_sha256:&remover_sha,
                installed_producer_sha256:&producer_sha,installed_inventory_sha256:&inventory_sha,protocol_sha256:binding.protocol_sha256,
                start:10,work:110_000_000_010,hard:120_000_000_010}).unwrap();
            let mut raw=capture.header(&request,state.digest_data(),&selected_raw,0).unwrap();
            for (row,(_,_,body)) in capture.controls.iter().zip(&bodies) {
                raw.extend_from_slice(&removal_snapshot_frame_data(row).unwrap());raw.extend_from_slice(body);
            }
            let genesis=parse_removal_genesis_data(raw.len() as u64,&"2".repeat(32),|at,out|{
                let at=at as usize;let count=out.len().min(raw.len()-at).min(13);out[..count].copy_from_slice(&raw[at..at+count]);Ok(count)
            }).unwrap();(genesis,selected,state,intent)
        }
        #[cfg(test)]
        pub(super) fn removal_rehome_data_checks() {
            use {RehomeSideData as Side,RehomeBoundaryData as Boundary,RehomeStateData as S,
                RehomeFreshData as F,RehomeVersionsData as V};
            let (genesis,selected,state,intent)=rehome_test_fixture();
            let plan=RehomeMoveSetData::from_genesis_data(&genesis,&selected,&state,&[&intent]).unwrap();
            assert_eq!(REHOME_CHILD,"reinstall-v1");assert_eq!(REHOME_TOP_LIMIT,275);
            let names=plan.moves_data().iter().map(|row|row.name_data()).collect::<Vec<_>>();
            assert_eq!(names.len(),7);assert_eq!(names.last(),Some(&"versions"));
            assert!(names[..names.len()-1].windows(2).all(|pair|pair[0]<pair[1]));
            assert!(!names.contains(&paths::MAINTENANCE_GATE_NAME));assert!(!names.contains(&paths::REGISTRATION_GATE_NAME));
            assert!(!names.contains(&paths::APP_NAME));assert!(!names.iter().any(|name|name.starts_with(".remove-")));
            assert_eq!(plan.files_data(),11);assert_eq!(plan.directories_data(),4);assert!(plan.owned_bytes_data().unwrap()<REHOME_WORK);
            let total=names.len();let state_position=plan.state_position_data().unwrap();
            for prefix in 0..=total {
                let sides=(0..total).map(|i|if i<prefix{Side::NewOnly}else{Side::OldOnly}).collect::<Vec<_>>();
                assert_eq!(plan.prefix_data(&sides).unwrap(),prefix);
                let observation=RehomeProgressData::from_observation_data(total,&sides).unwrap();
                assert_eq!(observation.observed_prefix_data(),prefix);assert_eq!(observation.last_return_data(),None);
                if prefix<total {
                    assert_eq!(rehome_boundary_data(total,prefix,state_position,
                        if state_position<prefix{S::Absent}else{S::ExactOld},V::ExactOld,F::Absent,F::Absent),Boundary::ContinueOldPrefix);
                    assert_eq!(rehome_boundary_data(total,prefix,state_position,S::RecordedNew,V::RecordedNew,F::RecordedNew,F::RecordedNew),Boundary::Refused);
                }
                let (directories,files,bytes)=plan.prefix_counts(prefix).unwrap();
                let root=Identity{dev:1,ino:800,mode:0o040700,uid:0,gid:0,links:2,size:64,
                    mtime:1,mtime_ns:0,ctime:2,ctime_ns:0};
                let reference=RehomeReferenceData::observed_data(&plan,root,0,prefix,directories,files,bytes,[8;32]).unwrap();
                assert_eq!(reference.complete_data(),prefix==total);assert_eq!(reference.storage_bytes_data(),bytes);
                assert!(reference.matches_data(&reference));
                let substituted=RehomeReferenceData::observed_data(&plan,Identity{ino:801,..root},0,prefix,directories,files,bytes,[8;32]).unwrap();
                assert!(!reference.matches_data(&substituted));
                assert!(RehomeReferenceData::observed_data(&plan,root,1,prefix,directories,files,bytes,[8;32]).is_err());
                assert!(RehomeReferenceData::observed_data(&plan,root,0,prefix,directories,files+1,bytes,[8;32]).is_err());
                assert!(RehomeReferenceData::observed_data(&plan,root,0,prefix,directories,files,bytes+1,[8;32]).is_err());
            }
            let mut sides=vec![Side::OldOnly;total];sides[total-1]=Side::NewOnly;
            assert!(plan.prefix_data(&sides).is_err());
            for bad in [Side::Both,Side::Neither,Side::Unknown] {sides=vec![Side::OldOnly;total];sides[0]=bad;assert!(plan.prefix_data(&sides).is_err());}
            assert!(plan.prefix_data(&[]).is_err());
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Absent,V::Absent,F::Absent,F::Absent),Boundary::FreshPreparation);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Absent,V::DistinctFreshEmpty,F::Absent,F::Absent),Boundary::FreshPreparation);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::RecordedNew,V::RecordedNew,F::RecordedNew,F::RecordedNew),Boundary::ObserveNewInstallation);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::PartialNew,V::PartialNew,F::PartialNew,F::PartialNew),Boundary::PreservePartialNew);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Absent,V::DistinctFreshEmpty,F::PartialNew,F::Absent),Boundary::PreservePartialNew);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::ExactOld,V::Absent,F::Absent,F::Absent),Boundary::Refused);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Absent,V::ExactOld,F::Absent,F::Absent),Boundary::Refused);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Foreign,V::RecordedNew,F::RecordedNew,F::RecordedNew),Boundary::Refused);
            assert_eq!(rehome_boundary_data(total,total,state_position,S::Unknown,V::Absent,F::Absent,F::Absent),Boundary::Refused);
            let id=Identity{dev:1,ino:900,mode:0o040755,uid:0,gid:0,links:2,size:64,mtime:1,mtime_ns:2,ctime:3,ctime_ns:4};
            for kind in [RehomeKindData::Metadata,RehomeKindData::Versions,RehomeKindData::InstallPhases,RehomeKindData::RestorePhases] {
                let before=Identity{mode:kind.mode(),links:if kind==RehomeKindData::Metadata{1}else{2},..id};
                let after=Identity{ctime:4,ctime_ns:5,..before};
                assert!(rehome_rebind_data(kind,before,0,after,0,after,0));
                for bad in [Identity{ino:901,..after},Identity{mode:0o040555,..after},Identity{uid:1,..after},
                    Identity{links:3,..after},Identity{size:65,..after},Identity{mtime:2,..after}] {
                    assert!(!rehome_rebind_data(kind,before,0,bad,0,bad,0));
                }
                assert!(!rehome_rebind_data(kind,before,0,after,0,before,0));
                assert!(!rehome_rebind_data(kind,before,0,after,1,after,1));
            }
            assert!(rehome_fresh_versions_data(id,Identity{ino:901,..id},0,0));
            assert!(!rehome_fresh_versions_data(id,id,0,0));
            assert!(!rehome_fresh_versions_data(id,Identity{ino:901,..id},0,1));
            let mut effects=RehomeProgressData::from_observation_data(2,&[Side::OldOnly;2]).unwrap();
            effects.begin_data(0).unwrap();effects.returned_data(ReturnedData::KnownSuccess).unwrap();
            assert_eq!(effects.last_return_data(),Some(ReturnedData::KnownSuccess));
            assert_eq!(effects.post_data(Err("same-original-post-failed")),Err("same-original-post-failed"));
            assert_eq!(effects.last_return_data(),Some(ReturnedData::KnownSuccess));assert_eq!(effects.observed_prefix_data(),0);
            assert!(effects.begin_data(0).is_err());assert_eq!(effects.first_failure_data(),Some("same-original-post-failed"));
            for returned in [ReturnedData::KnownRefusal,ReturnedData::Unknown] {
                let mut failed=RehomeProgressData::from_observation_data(2,&[Side::OldOnly;2]).unwrap();
                failed.begin_data(0).unwrap();failed.returned_data(returned).unwrap();assert!(failed.post_data(Ok(())).is_err());
                assert_eq!(failed.last_return_data(),Some(returned));assert_eq!(failed.observed_prefix_data(),0);
                assert!(failed.begin_data(0).is_err());
            }
            let mut success=RehomeProgressData::from_observation_data(2,&[Side::NewOnly,Side::OldOnly]).unwrap();
            assert_eq!(success.last_return_data(),None);success.begin_data(1).unwrap();success.returned_data(ReturnedData::KnownSuccess).unwrap();
            success.post_data(Ok(())).unwrap();assert_eq!(success.observed_prefix_data(),2);assert!(success.begin_data(1).is_err());
            let work=plan.owned_bytes_data().unwrap();let count=2*plan.directories_data()+plan.files_data();
            assert_eq!(rehome_audit_quote_data(plan.directories_data(),plan.files_data(),2,24576-2*count,91,
                REMOVAL_SNAPSHOT_WORK as usize-work-65536-8192,work,0,plan.bytes_data()).unwrap(),24576);
            assert!(rehome_audit_quote_data(plan.directories_data(),plan.files_data(),2,24577-2*count,91,0,work,0,plan.bytes_data()).is_err());
            assert!(rehome_audit_quote_data(plan.directories_data(),plan.files_data(),1,0,92,0,work,0,plan.bytes_data()).is_err());
            assert!(rehome_audit_quote_data(75,484,usize::MAX,0,0,0,0,0,0).is_err());
            assert!(rehome_audit_quote_data(76,484,1,0,0,0,0,0,0).is_err());
            assert!(rehome_audit_quote_data(75,485,1,0,0,0,0,0,0).is_err());
            assert!(rehome_audit_quote_data(75,484,1,0,0,0,REHOME_WORK+1,0,0).is_err());
            assert!(rehome_audit_quote_data(75,484,1,0,0,0,0,installation_record::PAYLOAD_LIMIT,1).is_err());
            drop(plan);
            // Same real decoded State/Intent and sole parsed snapshot; every
            // foreign/missing/hash mutation is rejected by the production set.
            let (mut bad,selected,state,intent)=rehome_test_fixture();
            bad.spans.controls.iter_mut().find(|row|row.path==transaction::STATE_NAME).unwrap().digest[0]^=1;
            assert!(RehomeMoveSetData::from_genesis_data(&bad,&selected,&state,&[&intent]).is_err());
            let (mut bad,selected,state,intent)=rehome_test_fixture();
            bad.spans.controls.iter_mut().find(|row|row.kind==0 && row.path.contains("staging-created")).unwrap().path="private-unknown.json".into();
            assert!(RehomeMoveSetData::from_genesis_data(&bad,&selected,&state,&[&intent]).is_err());
            let (mut bad,selected,state,intent)=rehome_test_fixture();
            bad.spans.controls.retain(|row|!row.path.contains("staging-created"));
            assert!(RehomeMoveSetData::from_genesis_data(&bad,&selected,&state,&[&intent]).is_err());
            assert!(RehomeMoveSetData::from_genesis_data(&genesis,&selected,&state,&[]).is_err());
            assert!(RehomeMoveSetData::from_genesis_data(&genesis,&selected,&state,&[&intent,&intent]).is_err());
        }

        #[cfg(test)]
        fn removal_archive_test_row(number:u64)->RemovalArchiveReference {
            let identity=Identity {dev:1,ino:100+number,mode:0o040700,uid:0,gid:0,links:2,size:64,
                mtime:1,mtime_ns:2,ctime:3,ctime_ns:4};
            RemovalArchiveReference {name:format!(".remove-{number:032x}"),identity,flags:0,request:None,app:None,snapshot:None,attempt:None,
                files:[Some(RemovalArchiveFileReference {identity:Identity {ino:1000+number,mode:0o100600,links:1,size:0,..identity},
                    flags:0,len:0,digest:Sha256::digest(b"").into(),shape:RemovalArchiveShape::WritingPrefix}),None,None,None,None,None]}
        }
        #[cfg(test)]
        fn removal_archive_test_table(count:usize)->RemovalArchiveCensus {
            let mut table=RemovalArchiveCensus::empty(0).unwrap();
            for number in 3..3+count as u64 {table.add(removal_archive_test_row(number)).unwrap();}table
        }
        #[cfg(test)]
        fn removal_archive_test_snapshot(intel:bool,prior:usize)->(Vec<u8>,usize) {
            removal_archive_test_snapshot_with_table(intel,removal_archive_test_table(prior))
        }
        #[cfg(test)]
        fn removal_archive_test_snapshot_with_table(intel:bool,table:RemovalArchiveCensus)->(Vec<u8>,usize) {
            use mobile_release_desktop::macos_remove_protocol::{BindingData,BindingInputData,TargetData};
            let release=if intel {"macos26-x86_64-data-3"}else{"macos26-arm64-data-3"};
            let selected=serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"current":{
                "profile":if intel {"fixed-macos26-x86_64-maintenance-v2"}else{"fixed-macos26-arm64-maintenance-v2"},
                "packageIdentifier":paths::PACKAGE_ID,"bundleIdentifier":paths::BUNDLE_ID,"packageVersion":"0.3.0",
                "release":release,"sourceCommit":"3".repeat(40),"protocolSha256":"7".repeat(64),
                "runtimeManifestSha256":"a".repeat(64),"inventorySha256":"6".repeat(64),
                "signingPolicySha256":"b".repeat(64),"packageSha256":"c".repeat(64)},"acceptedPredecessors":[]})).unwrap();
            let request=BindingData::new_data(BindingInputData {request_id:&"1".repeat(32),root_nonce:&"2".repeat(32),
                source_commit:&"3".repeat(40),release,target:if intel {TargetData::Intel}else{TargetData::Arm64},
                remove_producer_sha256:&"4".repeat(64),installed_producer_sha256:&"5".repeat(64),
                installed_inventory_sha256:&"6".repeat(64),protocol_sha256:&"7".repeat(64),
                start:10,work:110_000_000_010,hard:120_000_000_010}).unwrap();
            let identity=Identity {dev:1,ino:2,mode:0o040755,uid:0,gid:0,links:2,size:64,
                mtime:1,mtime_ns:2,ctime:3,ctime_ns:4};
            let mut children=vec![("control.json".to_owned(),9)];
            for row in table.rows(){children.push((row.name.clone(),row.identity.ino));}
            children.sort_by(|a,b|a.0.cmp(&b.0));
            let row=RemovalSnapshotControl {path:"control.json".into(),identity:Identity{ino:9,mode:0o100444,links:1,size:3,..identity},
                flags:0,size:3,digest:Sha256::digest(b"raw").into(),kind:0,held:None};
            let mut capture=RemovalSnapshotCapture {root:0,versions:None,prior_archives:None,controls:vec![row],
                directories:vec![RemovalSnapshotDirectory{path:String::new(),identity,flags:0,children}],
                complete:false,quote:Some((0,0)),failed:false};
            // Real fixed encoder/capture APIs fed inert DATA, never a signer,
            // Book or filesystem. Reader roundtrip must match their bytes.
            capture.finish(table).unwrap();
            let mut bytes=capture.header(&request,&"8".repeat(64),&selected,0).unwrap();
            let header=bytes.len();let frame=removal_snapshot_frame_data(&capture.controls[0]).unwrap();
            bytes.extend_from_slice(&frame);bytes.extend_from_slice(b"raw");(bytes,header)
        }
        #[cfg(test)]
        fn removal_archive_test_parse(bytes:&[u8],sealed:bool)->Result<(bool,Option<ArchiveHeader>,[u8;32])> {
            parse_removal_snapshot_data(bytes.len() as u64,sealed,&"2".repeat(32),|at,out|{
                let at=at as usize;check(at<=bytes.len(),"test-source-offset")?;
                // Deliberately short positive reads exercise exact advancement.
                let count=out.len().min(bytes.len()-at).min(7);out[..count].copy_from_slice(&bytes[at..at+count]);Ok(count)
            })
        }
        #[cfg(test)]
        pub(super) fn removal_archive_data_checks() {
            removal_rehome_data_checks();
            removal_history_data_checks();
            for (snapshot,admission) in [(None,None),(Some((0o100600,false)),None),
                (Some((0o100600,true)),None),(Some((0o100444,true)),None),(Some((0o100444,true)),Some(0o100600))] {
                assert!(archive_preadmission_shape_data(snapshot,admission));
            }
            for (snapshot,admission) in [(None,Some(0o100600)),(Some((0o100600,false)),Some(0o100600)),
                (Some((0o100444,false)),None),(Some((0o100444,true)),Some(0o100444))] {
                assert!(!archive_preadmission_shape_data(snapshot,admission));
            }
            for intel in [false,true] {
                let (bytes,header)=removal_archive_test_snapshot(intel,0);
                let (complete,parsed,digest)=removal_archive_test_parse(&bytes,true).unwrap();
                assert!(complete);assert_eq!(digest,<[u8;32]>::from(Sha256::digest(&bytes)));
                assert_eq!(parsed.as_ref().unwrap().target,
                    if intel {mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Intel}
                    else {mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64});
                // Exhaustive cuts of this tiny real-encoder fixture. Empty and
                // every valid field/body prefix is inert0600, never sealed444.
                for cut in 0..bytes.len() {
                    let outcome=removal_archive_test_parse(&bytes[..cut],false).unwrap();assert!(!outcome.0);
                    assert!(removal_archive_test_parse(&bytes[..cut],true).is_err());
                }
                assert!(removal_archive_test_parse(&bytes,false).unwrap().0);
                let record=parsed.unwrap().admission(digest).unwrap();
                for cut in 0..=record.bytes_data().len() {
                    assert!(archive_admission_chunk_data(record.bytes_data(),0,&record.bytes_data()[..cut]));
                }
                assert!(!archive_admission_chunk_data(record.bytes_data(),0,b"private unrelated text"));
                assert!(!archive_admission_chunk_data(record.bytes_data(),record.bytes_data().len(),b"x"));
                let mut trailing=bytes.clone();trailing.push(0);assert!(removal_archive_test_parse(&trailing,false).is_err());
                let mut corrupt=bytes.clone();corrupt[0]^=1;assert!(removal_archive_test_parse(&corrupt[..1],false).is_err());
                corrupt=bytes.clone();corrupt[23]=3;assert!(removal_archive_test_parse(&corrupt,false).is_err());
                corrupt=bytes.clone();corrupt[24..26].copy_from_slice(&31u16.to_be_bytes());
                assert!(removal_archive_test_parse(&corrupt[..26],false).is_err());
                let selection_length=23+1+14+32+32+40+4*64;
                for length in [0u32,16385] {corrupt=bytes.clone();corrupt[selection_length..selection_length+4].copy_from_slice(&length.to_be_bytes());
                    assert!(removal_archive_test_parse(&corrupt[..selection_length+4],false).is_err());}
                for count in [0u16,489] {corrupt=bytes.clone();corrupt[header-2..header].copy_from_slice(&count.to_be_bytes());
                    assert!(removal_archive_test_parse(&corrupt[..header],false).is_err());}
                corrupt=bytes.clone();corrupt[header]=5;assert!(removal_archive_test_parse(&corrupt[..header+1],false).is_err());
                let identity=header+1+2+"control.json".len();
                corrupt=bytes.clone();corrupt[identity+16..identity+20].copy_from_slice(&0o100600u32.to_be_bytes());
                assert!(removal_archive_test_parse(&corrupt[..identity+20],false).is_err());
                corrupt=bytes.clone();let last=corrupt.len()-1;corrupt[last]^=1;
                assert!(removal_archive_test_parse(&corrupt,false).is_err());
                assert!(parse_removal_snapshot_data(bytes.len() as u64,true,&"2".repeat(32),|_,_|Ok(0)).is_err());
                assert!(parse_removal_snapshot_data(bytes.len() as u64,true,&"2".repeat(32),|at,out|{
                    if at==bytes.len() as u64 {out[0]=1;return Ok(1);}
                    let at=at as usize;let n=out.len().min(bytes.len()-at);out[..n].copy_from_slice(&bytes[at..at+n]);Ok(n)
                }).is_err());
            }
            for prior in [1,64] {let (bytes,_)=removal_archive_test_snapshot(false,prior);
                assert!(removal_archive_test_parse(&bytes,true).unwrap().0);}
            for path in ["../x","a/../b","a/b/c/d","/absolute","foreign spaced"] {
                assert!(!archive_relative_path_data(path,false));
            }
            assert!(!archive_control_path_data(0,"@remove/producer.json"));
            assert!(archive_control_path_data(1,"@remove/producer.json"));
            assert!(!archive_control_path_data(1,"@remove/producer.sig"));
            let mut table=removal_archive_test_table(64);assert!(table.owned_bytes().unwrap()<=REMOVAL_ARCHIVE_TABLE);
            assert!(table.add(removal_archive_test_row(99)).is_err());
            let row=removal_archive_test_row(3);assert!(archive_directory_data(row.identity,row.flags,true));
            assert!(!archive_directory_data(Identity{mode:0o040755,..row.identity},0,true));
            assert!(!archive_directory_data(row.identity,1,true));
            let file=row.files[0].as_ref().unwrap();assert!(archive_file_data(file.identity,0,0));
            for id in [Identity{links:2,..file.identity},Identity{uid:1,..file.identity},
                Identity{gid:1,..file.identity},Identity{mode:0o120600,..file.identity},Identity{size:-1,..file.identity}] {
                assert!(!archive_file_data(id,0,0));
            }
            let mut scan=RemovalArchiveScan::first(0);scan.install(removal_archive_test_table(1)).unwrap();scan.complete().unwrap();
            assert!(scan.current.as_ref().unwrap().fresh(&"1".repeat(32),&format!("{:032x}",3)).is_err());
            assert!(scan.current.as_ref().unwrap().fresh(&"1".repeat(32),&"2".repeat(32)).is_ok());
            scan.second().unwrap();scan.install(removal_archive_test_table(1)).unwrap();scan.complete().unwrap();
            let second=scan.take().unwrap();assert_eq!(second.rows().len(),1);assert!(scan.first.is_none() && scan.current.is_none());
            assert!(scan.take().is_err());
            for drift in 0..5 {
                let mut scan=RemovalArchiveScan::first(0);scan.install(removal_archive_test_table(1)).unwrap();scan.complete().unwrap();scan.second().unwrap();
                let mut changed=removal_archive_test_table(1);
                match drift {0=>changed.rows[0].identity.ctime+=1,1=>changed.rows[0].files[0].as_mut().unwrap().digest[0]^=1,
                    2=>changed.rows[0].files[0].as_mut().unwrap().len+=1,3=>changed.rows[0].flags=1,_=>changed.rows.clear()}
                assert!(scan.install(changed).is_err());assert!(scan.phase==RemovalArchivePhase::Refused);
                assert!(scan.install(removal_archive_test_table(1)).is_err());assert!(scan.take().is_err());
            }
            let mut failed=RemovalArchiveScan::first(0);assert!(failed.take().is_err());
            assert!(failed.phase==RemovalArchivePhase::Refused);
            assert_eq!(removal_archive_storage_sum_data(installation_record::PAYLOAD_LIMIT-1,1),Ok(installation_record::PAYLOAD_LIMIT));
            assert!(removal_archive_storage_sum_data(installation_record::PAYLOAD_LIMIT,1).is_err());
            assert!(removal_archive_storage_sum_data(u64::MAX,1).is_err());
            assert_eq!(removal_archive_raw_hash(0,|_,_|Ok(0)).unwrap(),<[u8;32]>::from(Sha256::digest(b"")));
            assert!(removal_archive_raw_hash(1,|_,_|Ok(0)).is_err());
            assert!(removal_archive_raw_hash(0,|_,out|{out[0]=0;Ok(1)}).is_err());
            assert_eq!(removal_archive_raw_hash(1,|_,_|Err("original-read-failed")),Err("original-read-failed"));
        }
        #[cfg(test)]
        fn removal_history_test_file(identity:Identity,slot:usize,bytes:&[u8],mode:u32)->RemovalArchiveFileReference {
            RemovalArchiveFileReference {identity:Identity {ino:identity.ino+1000+slot as u64,mode,links:1,size:bytes.len() as i64,..identity},
                flags:0,len:bytes.len() as u64,digest:Sha256::digest(bytes).into(),
                shape:if mode==0o100444 {RemovalArchiveShape::SealedBody}else{RemovalArchiveShape::WritingPrefix}}
        }
        #[cfg(test)]
        fn removal_history_test_chain(count:usize)->RemovalArchiveCensus {
            use mobile_release_desktop::macos_remove_record::RemovalRecordData;
            assert!((1..=64).contains(&count));
            let (bytes,_)=removal_archive_test_snapshot(false,0);
            let (_,header,sha)=removal_archive_test_parse(&bytes,true).unwrap();let header=header.unwrap();
            let mut current=header.admission(sha).unwrap();
            let mut rows=Vec::new();
            for index in 0..count {
                if index>0 {current=current.new_attempt_data(&format!("{:032x}",100+index),&format!("{:032x}",200+index),index,
                    current.binding_data()).unwrap();}
                let mut row=removal_archive_test_row(3+index as u64);row.name=format!(".remove-{}",current.root_nonce_data());
                row.files=std::array::from_fn(|_|None);row.request=Some(archive_hex_data(current.request_id_data()).unwrap());
                if index==0 {
                    row.files[0]=Some(removal_history_test_file(row.identity,0,&bytes,0o100444));
                    row.snapshot=Some(header.summary(sha).unwrap());
                }
                row.files[1]=Some(removal_history_test_file(row.identity,1,current.bytes_data(),0o100444));
                row.attempt=Some(RemovalAttemptData::from_record(&current,1).unwrap());rows.push(row);
            }
            // Original scans use sorted actual names; graph resolution must not
            // depend on generation/time/lexical order. Here genesis sorts LAST.
            rows.sort_by(|a,b|a.name.cmp(&b.name));let mut table=RemovalArchiveCensus::empty(0).unwrap();
            for row in rows {table.add(row).unwrap();}table.resolve_history_data().unwrap();
            assert_eq!(current.bytes_data(),RemovalRecordData::parse_shape_data(current.bytes_data()).unwrap().bytes_data());table
        }
        #[cfg(test)]
        fn removal_history_data_checks() {
            use mobile_release_desktop::macos_remove_record::{RemovalRecordData,PrefixData as P,FailureKindData as F};
            assert_eq!(REMOVAL_ARCHIVE_NAMES,["snapshot-v2","admission.json","app-withdrawn.json",
                "payload-roster-removal.json","payload-absent-observed.json","first-failure.json"]);
            let (snapshot,_)=removal_archive_test_snapshot(false,0);
            let (_,header,sha)=removal_archive_test_parse(&snapshot,true).unwrap();let header=header.unwrap();
            let original=header.admission(sha).unwrap();let nonce=original.root_nonce_data();
            let spans=parse_removal_genesis_data(snapshot.len() as u64,nonce,|at,out|{
                let at=at as usize;let n=out.len().min(snapshot.len()-at).min(11);
                out[..n].copy_from_slice(&snapshot[at..at+n]);Ok(n)
            }).unwrap();
            assert_eq!(spans.whole_sha256_data(),&sha);assert_eq!(spans.root_nonce_data(),nonce);
            assert!(spans.binding_data().unwrap().matches_data(original.binding_data()));
            assert!(!spans.selected_bytes_data().is_empty());assert_eq!(spans.controls_data().len(),1);
            let control=&spans.controls_data()[0];assert_eq!(control.path_data(),"control.json");assert_eq!(control.kind_data(),0);
            let start=control.offset_data() as usize;let end=start+control.len_data() as usize;
            assert_eq!(&snapshot[start..end],b"raw");assert_eq!(control.digest_data(),&<[u8;32]>::from(Sha256::digest(b"raw")));
            assert_eq!(control.identity_data().size,3);assert_eq!(control.flags_data(),0);
            assert!(spans.owned_bytes_data().unwrap()<=REMOVAL_HISTORY_SPANS);
            let mut v1=snapshot.clone();v1[..REMOVAL_SNAPSHOT_MAGIC.len()].copy_from_slice(b"MRK-REMOVE-SNAPSHOT-V1\0");
            assert!(removal_archive_test_parse(&v1,false).is_err());
            assert!(parse_removal_genesis_data(REMOVAL_SNAPSHOT_LIMIT+1,nonce,|_,_|panic!("overbound read")).is_err());

            // Six fixed reference slots and optional named app DATA roundtrip
            // through the REAL v2 encoder/parser. This is not a historic signer
            // or recursive admission of any referenced body.
            for app in [false,true] {
                let mut row=removal_archive_test_row(3);row.files=std::array::from_fn(|slot|Some(
                    removal_history_test_file(row.identity,slot,b"{}",0o100444)));
                if app {row.files[3]=Some(removal_history_test_file(row.identity,3,b"{",0o100600));row.files[4]=None;
                    row.app=Some((Identity {mode:0o040555,ino:900,..row.identity},0));}
                assert!(removal_archive_reference_shape_data(std::array::from_fn(|i|row.files[i].as_ref().map(|f|f.identity.mode)),app));
                let mut table=RemovalArchiveCensus::empty(0).unwrap();table.add(row).unwrap();
                let (encoded,_)=removal_archive_test_snapshot_with_table(false,table);
                assert!(removal_archive_test_parse(&encoded,true).unwrap().0);
            }
            for bad in [
                [None,Some(0o100600),Some(0o100444),None,None,None],
                [Some(0o100600),Some(0o100444),None,None,None,None],
                [None,Some(0o100444),None,Some(0o100444),None,None],
                [None,Some(0o100444),Some(0o100600),Some(0o100600),None,None],
                [None,None,None,None,None,Some(0o100444)],
            ] {assert!(!removal_archive_reference_shape_data(bad,false));}
            assert!(!removal_archive_reference_shape_data([None,Some(0o100444),None,None,None,None],true));
            assert!(!removal_archive_reference_shape_data([Some(0o100444);6],true));
            let app=Identity {mode:0o040555,..removal_archive_test_row(3).identity};
            assert!(removal_archive_app_data(app,0));assert!(!removal_archive_app_data(Identity{mode:0o120555,..app},0));
            assert!(!removal_archive_app_data(Identity{uid:1,..app},0));assert!(!removal_archive_app_data(app,1));

            // Actual closed Record parser + transitions, not a second JSON
            // implementation. The same-phase failure is based on the highest
            // observed complete444 body, even if its later fsync failed.
            let mut last=None;let mut request=None;
            removal_archive_record_data(1,0o100444,original.bytes_data(),nonce,Some((&header,sha)),&mut last,&mut request).unwrap();
            let next=original.next_prefix_data(P::AppWithdrawn,original.binding_data()).unwrap();
            for cut in 0..=next.bytes_data().len() {
                removal_history_writer_prefix_data(&original,2,&next.bytes_data()[..cut]).unwrap();
            }
            removal_archive_record_data(2,0o100600,next.bytes_data(),nonce,None,&mut last,&mut request).unwrap();
            assert_eq!(last.as_ref().unwrap().0.prefix_data(),P::AdmissionRecorded);
            let failed=original.first_failure_latched_data(F::Persistence,original.binding_data()).unwrap();
            removal_archive_record_data(5,0o100444,failed.bytes_data(),nonce,None,&mut last,&mut request).unwrap();
            assert_eq!(last.as_ref().unwrap().0.first_failure_data().unwrap().phase,P::AdmissionRecorded);
            assert!(removal_archive_record_data(2,0o100444,next.bytes_data(),nonce,None,&mut last,&mut request).is_err());
            last=None;
            removal_archive_record_data(1,0o100444,original.bytes_data(),nonce,Some((&header,sha)),&mut last,&mut request).unwrap();
            removal_archive_record_data(2,0o100444,next.bytes_data(),nonce,None,&mut last,&mut request).unwrap();
            assert!(removal_archive_record_data(5,0o100444,failed.bytes_data(),nonce,None,&mut last,&mut request).is_err());
            let current_failure=next.first_failure_latched_data(F::Persistence,next.binding_data()).unwrap();
            removal_archive_record_data(5,0o100444,current_failure.bytes_data(),nonce,None,&mut last,&mut request).unwrap();
            assert_eq!(last.as_ref().unwrap().0.digest_data(),current_failure.digest_data());
            let skip=next.next_prefix_data(P::PayloadRosterRemoval,next.binding_data()).unwrap();
            let mut no_admission=None;let mut unknown=None;
            assert!(removal_archive_record_data(3,0o100444,skip.bytes_data(),nonce,None,&mut no_admission,&mut unknown).is_err());
            assert!(removal_archive_record_data(1,0o100444,original.bytes_data(),nonce,None,&mut no_admission,&mut unknown).is_err());
            assert!(removal_archive_record_data(1,0o100444,original.bytes_data(),nonce,Some((&header,[9;32])),
                &mut no_admission,&mut unknown).is_err());

            // Preserve a noncanonical REAL raw tip SHA. The private comparison
            // template must equal shared new_attempt_data byte for byte; its
            // closed tuple never hashes a reconstructed canonical predecessor.
            let mut raw=failed.bytes_data().to_vec();raw.extend_from_slice(b" \n");
            let old=RemovalRecordData::parse_shape_data(&raw).unwrap();assert_ne!(old.digest_data(),failed.digest_data());
            let before=RemovalAttemptData::from_record(&old,5).unwrap();
            let new_nonce="33333333333333333333333333333333";let dummy="22222222222222222222222222222222";
            for count in [2,64] {
                let actual=old.new_attempt_data(dummy,new_nonce,count-1,old.binding_data()).unwrap();
                assert_eq!(removal_linked_template_data(&before,new_nonce,count).unwrap(),actual.bytes_data());
                assert_eq!(actual.previous_attempt_data().unwrap().2,old.digest_data());
                assert_eq!(actual.binding_data().payload_roster_sha256,original.binding_data().payload_roster_sha256);
                assert!(actual.first_failure_data().is_none());assert!(old.first_failure_data().is_some());
                let fresh=old.new_attempt_data("44444444444444444444444444444444",new_nonce,count-1,old.binding_data()).unwrap();
                for cut in 0..=fresh.bytes_data().len() {
                    let seen=removal_linked_admission_prefix_data(&before,new_nonce,count,&fresh.bytes_data()[..cut]).unwrap();
                    if let Some(seen)=seen {assert_eq!(seen,[0x44;16]);}
                }
                assert_eq!(removal_linked_admission_prefix_data(&before,new_nonce,count,fresh.bytes_data()).unwrap(),Some([0x44;16]));
                let mut prior_mismatch=before;prior_mismatch.tip[0]^=1;
                assert!(removal_linked_admission_prefix_data(&prior_mismatch,new_nonce,count,fresh.bytes_data()).is_err());
                let text=std::str::from_utf8(fresh.bytes_data()).unwrap();
                for bad in [text.replace("\"previousAttempt\":","\"previousAttempts\":"),
                    text.replace("\"recordSha256\":","\"recordSha25\":"),text.replace(dummy,"22"),
                    text.replace("44444444444444444444444444444444","00000000000000000000000000000000")] {
                    assert!(removal_linked_admission_prefix_data(&before,new_nonce,count,bad.as_bytes()).is_err());
                }
                assert!(removal_linked_admission_prefix_data(&before,nonce,count,fresh.bytes_data()).is_err());
            }
            for count in [0,1,65,usize::MAX] {assert!(removal_linked_template_data(&before,new_nonce,count).is_err());}
            assert!(removal_linked_admission_prefix_data(&before,new_nonce,2,b"private unrelated text").is_err());

            for count in [1,2,64] {
                let table=removal_history_test_chain(count);assert!(table.has_admitted_history_data());
                assert_eq!(table.rows.iter().filter(|row|row.snapshot.is_some()).count(),1);
                assert_eq!((0..count).filter(|i|table.is_tip_data(*i)).count(),1);
                let root=table.rows.iter().position(|row|row.snapshot.is_some()).unwrap();
                assert!((0..count).all(|i|table.genesis_index_data(i)==Some(root)));
                for row in &table.rows {if row.attempt.unwrap().previous.is_some(){assert!(row.files[0].is_none() && row.app.is_none());}}
                assert!(table.owned_bytes().unwrap()<=REMOVAL_ARCHIVE_TABLE);
            }
            let mut full=removal_history_test_chain(64);
            // Valid sixty-fifth row: fixture inode arithmetic must not overflow,
            // and the name must follow the genesis that deliberately sorts last.
            let mut extra=removal_archive_test_row(99);
            extra.name=".remove-ffffffffffffffffffffffffffffffff".into();
            assert!(full.rows.last().unwrap().name<extra.name);
            assert!(full.add(extra).is_err());
            // Fresh exact tables per mutation avoid Clone/DTO authority and
            // deliberately exercise the ACTUAL production graph reducer.
            for change in 0..9 {
                let mut table=removal_history_test_chain(3);
                let child=table.rows.iter().position(|row|row.attempt.unwrap().previous.is_some()).unwrap();
                let root=table.genesis_index_data(child).unwrap();
                match change {
                    0=>table.rows[child].attempt.as_mut().unwrap().previous.as_mut().unwrap().tip[0]^=1,
                    1=>table.rows[child].attempt.as_mut().unwrap().previous.as_mut().unwrap().request=[0x77;16],
                    2=>table.rows[root].snapshot.as_mut().unwrap().binding.digests[4][0]^=1,
                    3=>table.rows[root].snapshot.as_mut().unwrap().nonce[0]^=1,
                    4=>table.rows[child].attempt.as_mut().unwrap().binding.digests[0][0]^=1,
                    5=>table.rows[child].request=table.rows[root].request,
                    6=>{table.rows[child].files[0]=Some(removal_history_test_file(table.rows[child].identity,0,b"x",0o100444));},
                    7=>table.rows[child].app=Some((Identity{mode:0o040555,..table.rows[child].identity},0)),
                    _=>table.rows[child].attempt.as_mut().unwrap().nonce=[0x99;16],
                }
                assert!(table.resolve_history_data().is_err(),"graph mutation {change}");
            }
            let mut fork=removal_history_test_chain(3);let root=fork.rows.iter().position(|row|row.snapshot.is_some()).unwrap();
            let parent=fork.rows[root].attempt.unwrap();
            for (index,row) in fork.rows.iter_mut().enumerate(){if index!=root {row.attempt.as_mut().unwrap().previous=Some(
                RemovalPreviousData {request:parent.request,nonce:parent.nonce,tip:parent.tip});}}
            assert!(fork.resolve_history_data().is_err());
            let mut cycle=removal_history_test_chain(2);
            let a=cycle.rows[0].attempt.unwrap();let b=cycle.rows[1].attempt.unwrap();
            for row in &mut cycle.rows {row.snapshot=None;row.files[0]=None;}
            cycle.rows[0].attempt.as_mut().unwrap().previous=Some(RemovalPreviousData{request:b.request,nonce:b.nonce,tip:b.tip});
            cycle.rows[1].attempt.as_mut().unwrap().previous=Some(RemovalPreviousData{request:a.request,nonce:a.nonce,tip:a.tip});
            assert!(cycle.resolve_history_data().is_err());

            for slot in 0..6 {
                for field in 0..5 {
                    let mut scan=RemovalArchiveScan::first(0);let mut first=removal_archive_test_table(1);
                    first.rows[0].files[slot]=Some(removal_history_test_file(first.rows[0].identity,slot,b"x",0o100444));
                    scan.install(first).unwrap();scan.complete().unwrap();scan.second().unwrap();
                    let mut changed=removal_archive_test_table(1);
                    changed.rows[0].files[slot]=Some(removal_history_test_file(changed.rows[0].identity,slot,b"x",0o100444));
                    let file=changed.rows[0].files[slot].as_mut().unwrap();
                    match field {0=>file.digest[0]^=1,1=>file.flags=1,2=>file.identity.ctime+=1,
                        3=>file.len+=1,_=>file.identity.mode=0o100600}
                    assert!(scan.install(changed).is_err());assert!(scan.phase==RemovalArchivePhase::Refused);
                }
            }
            let mut scan=RemovalArchiveScan::first(0);let mut first=removal_archive_test_table(1);
            first.rows[0].app=Some((app,0));scan.install(first).unwrap();scan.complete().unwrap();scan.second().unwrap();
            let mut changed=removal_archive_test_table(1);changed.rows[0].app=Some((Identity{ctime:app.ctime+1,..app},0));
            assert!(scan.install(changed).is_err());
            let spans=RemovalSemanticSpans::new();assert!(spans.memory(REMOVAL_HISTORY_SPANS+1).is_err());
            let root_quote=std::mem::size_of::<Vec<(String,u64)>>()+350*std::mem::size_of::<(String,u64)>()+350*255+65536+8192;
            assert_eq!(removal_archive_roster_quote_data(false,350,350*255,0),Ok(root_quote));assert!(root_quote<=256*1024);
            assert!(removal_archive_roster_quote_data(true,7,7*255,0).unwrap()<=128*1024);
            assert!(removal_archive_roster_quote_data(false,351,0,0).is_err());assert!(removal_archive_roster_quote_data(true,8,0,0).is_err());
            assert!(removal_archive_roster_quote_data(false,350,usize::MAX,1).is_err());
            let mut roster=vec![("b".to_owned(),2),("a".to_owned(),1)];roster.sort_unstable_by(|a,b|a.0.cmp(&b.0));
            assert!(roster.windows(2).all(|pair|pair[0].0<pair[1].0));
            assert_eq!(removal_archive_inode(&roster,"a"),Some(1));assert_eq!(removal_archive_inode(&roster,"c"),None);
            roster.push(("b".to_owned(),3));assert!(!roster.windows(2).all(|pair|pair[0].0<pair[1].0));
            assert_eq!(removal_archive_original_quote_data(64,0),Ok(512));
            assert_eq!(removal_archive_original_quote_data(64,64),Ok(640));
            assert!(removal_archive_original_quote_data(65,0).is_err());assert!(removal_archive_original_quote_data(1,2).is_err());
            assert_eq!(REMOVAL_ARCHIVE_TABLE*2,256*1024);assert_eq!(REMOVAL_ARCHIVE_PARSER,1024*1024);
            assert!(REMOVAL_ARCHIVE_TABLE*2+REMOVAL_ARCHIVE_PARSER<REMOVAL_SNAPSHOT_WORK as usize);
            // Initial snapshot POST is once Taken, final payload POST is a NEW
            // same-original read only after successful PostComplete. There is
            // no reset to Taken and no error/unfinished-read success credit.
            let mut scan=RemovalArchiveScan::first(0);scan.install(removal_archive_test_table(0)).unwrap();scan.complete().unwrap();
            scan.second().unwrap();scan.install(removal_archive_test_table(0)).unwrap();scan.complete().unwrap();let _same=scan.take().unwrap();
            scan.begin_post(0,true).unwrap();scan.complete_post(Ok(())).unwrap();
            scan.begin_post(0,false).unwrap();scan.complete_post(Ok(())).unwrap();
            assert!(scan.phase==RemovalArchivePhase::PostComplete);
            assert!(scan.begin_post(0,true).is_err());assert!(scan.phase==RemovalArchivePhase::Refused);
            for phase in [RemovalArchivePhase::FirstReading,RemovalArchivePhase::FirstComplete,RemovalArchivePhase::SecondReading,
                RemovalArchivePhase::SecondComplete,RemovalArchivePhase::Taken,RemovalArchivePhase::PostReading,RemovalArchivePhase::Refused] {
                let mut wrong=RemovalArchiveScan::first(0);wrong.phase=phase;
                assert!(wrong.begin_post(0,false).is_err());assert!(wrong.phase==RemovalArchivePhase::Refused);
            }
            let mut failed=RemovalArchiveScan::first(0);failed.phase=RemovalArchivePhase::PostComplete;
            failed.begin_post(0,false).unwrap();assert_eq!(failed.complete_post(Err("actual-first")),Err("actual-first"));
            assert!(failed.phase==RemovalArchivePhase::Refused);assert!(failed.complete_post(Ok(())).is_err());
        }

        // Removal-only plan captured by the SAME fully admitted second walker.
        // Only this module constructs nodes; wire/parser DATA cannot mint it.
        const REMOVAL_PLAN_NODES:usize=2*installation_record::FILE_LIMIT*(mobile_release_desktop::macos_install_maintenance::PREDECESSOR_LIMIT+1);
        pub(super) struct RemovalPayloadNode {
            pub(super) name:String, pub(super) identity:Identity, pub(super) flags:u32,
            pub(super) parent:Option<usize>, pub(super) generation:usize,
            pub(super) directory:bool, pub(super) children:Vec<usize>, expected_children:usize,
            pub(super) size:u64, pub(super) digest:[u8;32], pub(super) executable:bool,
            pub(super) held:Option<usize>, pub(super) complete:bool,
        }
        pub(super) struct RemovalPayloadGeneration {
            pub(super) release:String, pub(super) app_name:String,
            pub(super) inventory_sha256:String, pub(super) roots:[Option<usize>;2],
        }
        pub(super) struct RemovalPayloadPlan {
            pub(super) nodes:Vec<RemovalPayloadNode>, pub(super) generations:Vec<RemovalPayloadGeneration>,
            stack:[usize;17], stack_len:usize, active:Option<usize>,
            base_control:u64, charged:u64, failed:bool, pub(super) complete:bool,
        }
        impl RemovalPayloadPlan {
            pub(super) fn begin(book:&mut Install)->Result<()> {
                check(book.removal_payload_plan.is_none(),"removal-payload-plan-once")?;
                let base_control=book.removal_observation_control.ok_or("removal-payload-plan-budget")?;
                let initial=std::mem::size_of::<Self>() as u64;
                check(base_control.checked_add(initial).is_some_and(|n|n<=16*1024*1024),"removal-payload-plan-budget")?;
                book.removal_control_reserved=book.removal_control_reserved.checked_add(initial)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-payload-plan-budget")?;
                book.removal_payload_plan=Some(Self { nodes:Vec::new(),generations:Vec::new(),stack:[0;17],stack_len:0,
                    active:None,base_control,charged:initial,failed:false,complete:false });Ok(())
            }
            fn growth(&self,extra:usize,overlap:usize)->Result<()> {
                check(self.base_control.checked_add(self.charged).and_then(|n|n.checked_add(extra as u64))
                    .and_then(|n|n.checked_add(overlap as u64)).is_some_and(|n|n<=16*1024*1024),"removal-payload-plan-budget")
            }
            fn charge(&mut self,book:&mut Install,extra:usize)->Result<()> {
                self.growth(extra,0)?;
                self.charged=self.charged.checked_add(extra as u64).ok_or("removal-payload-plan-budget")?;
                book.removal_control_reserved=book.removal_control_reserved.checked_add(extra as u64)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-payload-plan-budget")?;Ok(())
            }
            fn reserve_nodes(&mut self,book:&mut Install)->Result<()> {
                check(self.nodes.len()<REMOVAL_PLAN_NODES,"removal-payload-plan-count")?;
                if self.nodes.len()==self.nodes.capacity() {
                    let old=self.nodes.capacity();let next=old.max(16).checked_mul(2).ok_or("removal-payload-plan-count")?.min(REMOVAL_PLAN_NODES);
                    let unit=std::mem::size_of::<RemovalPayloadNode>();
                    self.growth((next-old)*unit,old*unit)?;
                    self.nodes.try_reserve_exact(next-self.nodes.len()).map_err(|_|"removal-payload-plan-allocation")?;
                    check(self.nodes.capacity()<=next,"removal-payload-plan-allocation")?;
                    self.charge(book,(self.nodes.capacity()-old)*unit)?;
                }Ok(())
            }
            pub(super) fn finish(&mut self)->Result<()> {
                check(!self.failed && !self.complete && self.active.is_none() && self.stack_len==0
                    && !self.generations.is_empty() && self.generations.len()<=9
                    && self.generations.iter().all(|g|g.roots.iter().all(Option::is_some))
                    && self.nodes.iter().all(|n|n.complete && n.children.len()==n.expected_children),"removal-payload-plan-incomplete")?;
                self.complete=true;Ok(())
            }
            pub(super) fn charged_bytes(&self)->u64 { self.charged }
        }
        fn payload_plan_edit(book:&mut Install,operation:impl FnOnce(&mut RemovalPayloadPlan,&mut Install)->Result<()>)->Result<()> {
            let Some(mut plan)=book.removal_payload_plan.take() else { return Ok(()); };
            let result=if plan.failed || plan.complete {Err("removal-payload-plan-phase")}else{operation(&mut plan,book)};
            if result.is_err(){plan.failed=true;}book.removal_payload_plan=Some(plan);result
        }
        fn payload_generation_begin(book:&mut Install,generation:&GenerationData)->Result<()> {
            payload_plan_edit(book,|plan,book| {
                check(plan.active.is_none() && plan.stack_len==0 && plan.generations.len()<9,"removal-payload-plan-generation")?;
                let binding=generation.release_data().binding_data();
                check(!plan.generations.iter().any(|g|g.release==binding.release),"removal-payload-plan-generation")?;
                let app_bound=if generation.retained_invocation_data().is_some(){255}else{paths::APP_NAME.len()};
                let old=plan.generations.capacity();let unit=std::mem::size_of::<RemovalPayloadGeneration>();
                let extra=if old==plan.generations.len(){(9-old)*unit}else{0};
                plan.growth(extra+binding.release.len()+app_bound+binding.inventory_sha256.len(),if extra!=0{old*unit}else{0})?;
                let app_name=match generation.retained_invocation_data() {None=>paths::APP_NAME.to_owned(),
                    Some(id)=>data(transaction::retained_app_name_data(id))?};
                check(app_name.capacity()<=app_bound,"removal-payload-plan-allocation")?;
                if extra!=0 {plan.generations.try_reserve_exact(9-plan.generations.len()).map_err(|_|"removal-payload-plan-allocation")?;
                    check(plan.generations.capacity()<=9,"removal-payload-plan-allocation")?;}
                let release=binding.release.to_owned();let inventory_sha256=binding.inventory_sha256.to_owned();
                plan.charge(book,(plan.generations.capacity()-old)*unit+release.capacity()+app_name.capacity()+inventory_sha256.capacity())?;
                let index=plan.generations.len();plan.generations.push(RemovalPayloadGeneration {release,app_name,inventory_sha256,roots:[None,None]});
                plan.active=Some(index);Ok(())
            })
        }
        fn payload_generation_end(book:&mut Install)->Result<()> {
            payload_plan_edit(book,|plan,_| {
                let index=plan.active.ok_or("removal-payload-plan-generation")?;
                check(plan.stack_len==0 && plan.generations[index].roots.iter().all(Option::is_some),"removal-payload-plan-generation")?;
                plan.active=None;Ok(())
            })
        }
        fn payload_directory_enter(book:&mut Install,original:usize,prefix:&str,depth:usize,children:usize)->Result<()> {
            payload_plan_edit(book,|plan,book| {
                let generation=plan.active.ok_or("removal-payload-plan-generation")?;
                check(depth<17 && plan.stack_len==depth && children<=installation_record::FILE_LIMIT,"removal-payload-plan-depth")?;
                let root_kind=if depth==0 {match prefix {"app"=>Some(0),"runtime"=>Some(1),_=>return Err("removal-payload-plan-root")}}else{None};
                plan.reserve_nodes(book)?;
                let name=if root_kind==Some(0) {plan.generations[generation].app_name.as_str()}
                    else {book.originals[original].name.as_str()};
                check((component(name)||root_kind==Some(0)&&name==paths::APP_NAME) && name.len()<=255,"removal-payload-plan-name")?;
                plan.growth(name.len()+children*std::mem::size_of::<usize>(),0)?;
                let name=name.to_owned();let parent=if depth==0{None}else{Some(plan.stack[depth-1])};
                let mut child_nodes=Vec::new();child_nodes.try_reserve_exact(children).map_err(|_|"removal-payload-plan-allocation")?;
                check(child_nodes.capacity()<=children,"removal-payload-plan-allocation")?;
                plan.charge(book,name.capacity()+child_nodes.capacity()*std::mem::size_of::<usize>())?;
                let actual=stat::fstat(book.fd(original)?).map_err(|_|"removal-payload-plan-stat")?;
                check(Identity::of(&actual)==book.identity(original)? && actual.st_flags==0,"removal-payload-plan-original")?;
                let index=plan.nodes.len();plan.nodes.push(RemovalPayloadNode {name,identity:Identity::of(&actual),flags:0,parent,generation,
                    directory:true,children:child_nodes,expected_children:children,size:0,digest:[0;32],executable:false,
                    held:if root_kind==Some(0)&&generation==0{Some(original)}else{None},complete:false});
                if let Some(parent)=parent {
                    let node=&mut plan.nodes[parent];check(node.children.len()<node.expected_children,"removal-payload-plan-roster")?;node.children.push(index);
                } else if let Some(kind)=root_kind {check(plan.generations[generation].roots[kind].is_none(),"removal-payload-plan-root")?;plan.generations[generation].roots[kind]=Some(index);}
                plan.stack[depth]=index;plan.stack_len=depth+1;Ok(())
            })
        }
        fn payload_file_observed(book:&mut Install,original:usize,entry:&Entry,depth:usize)->Result<()> {
            payload_plan_edit(book,|plan,book| {
                check(depth<17 && plan.stack_len==depth+1,"removal-payload-plan-depth")?;
                let parent=plan.stack[depth];let generation=plan.active.ok_or("removal-payload-plan-generation")?;
                plan.reserve_nodes(book)?;
                let name=book.originals[original].name.as_str();check(component(name)&&name.len()<=255,"removal-payload-plan-name")?;
                plan.growth(name.len(),0)?;
                let name=name.to_owned();
                let actual=stat::fstat(book.fd(original)?).map_err(|_|"removal-payload-plan-stat")?;
                check(Identity::of(&actual)==book.identity(original)? && actual.st_flags==0
                    && actual.st_size>=0 && actual.st_size as u64==entry.size,"removal-payload-plan-original")?;
                let digest=worker::removal_hex_data::<32>(&entry.sha256)?;
                plan.charge(book,name.capacity())?;let index=plan.nodes.len();
                plan.nodes.push(RemovalPayloadNode {name,identity:Identity::of(&actual),flags:0,parent:Some(parent),generation,directory:false,
                    children:Vec::new(),expected_children:0,size:entry.size,digest,executable:entry.executable,held:None,complete:true});
                let node=&mut plan.nodes[parent];check(node.children.len()<node.expected_children,"removal-payload-plan-roster")?;node.children.push(index);Ok(())
            })
        }
        fn payload_directory_leave(book:&mut Install,depth:usize)->Result<()> {
            payload_plan_edit(book,|plan,_| {
                check(depth<17 && plan.stack_len==depth+1,"removal-payload-plan-depth")?;
                let index=plan.stack[depth];let node=&mut plan.nodes[index];
                check(node.children.len()==node.expected_children,"removal-payload-plan-roster")?;
                node.complete=true;plan.stack_len=depth;Ok(())
            })
        }

        // Fixed removal-only capture of the SAME complete second observation.
        // These are comparison bytes/identities, never a parser-made permission.
        pub(super) const REMOVAL_SNAPSHOT_WORK: u64 = 2 * 1024 * 1024;
        const SNAPSHOT_CONTROLS: usize = 488;
        const SNAPSHOT_DIRECTORIES: usize = 75;
        const SNAPSHOT_CHILDREN: usize = 642;
        const SNAPSHOT_HEADER: usize = 1024 * 1024;
        pub(super) const REMOVAL_SNAPSHOT_LIMIT: u64 = 16 * 1024 * 1024;
        pub(super) const REMOVAL_SNAPSHOT_MAGIC: &[u8] = b"MRK-REMOVE-SNAPSHOT-V2\0";
        pub(super) struct RemovalSnapshotControl {
            pub(super) path: String, pub(super) identity: Identity, pub(super) flags: u32,
            pub(super) size: u64, pub(super) digest: [u8;32], pub(super) kind: u8,
            pub(super) held: Option<usize>,
        }
        struct RemovalSnapshotDirectory {
            path: String, identity: Identity, flags: u32, children: Vec<(String,u64)>,
        }
        #[derive(Clone,Copy,PartialEq,Eq)]
        enum RemovalRemainingPresence {
            Present {identity:Identity,flags:u32},
            // The parent was freshly held/named and THIS child had actual
            // nofollow ENOENT. For a directory this covers its signed subtree;
            // it does not fabricate descendant FDs or old inode authority.
            Absent {parent:Identity},
        }
        struct RemovalRemainingNode {
            generation:usize,path:String,parent:Option<usize>,directory:bool,
            size:u64,digest:[u8;32],executable:bool,presence:RemovalRemainingPresence,
        }
        struct RemovalRemainingGeneration {release:String,inventory:String,app_name:String,current:bool}
        pub(super) struct RemovalRemainingPlan {
            nodes:Vec<RemovalRemainingNode>,generations:Vec<RemovalRemainingGeneration>,
            stack:[Option<usize>;17],active:Option<usize>,base:u64,transient:usize,
            expected_files:u64,present_files:u64,present_bytes:u64,expected_directories:u64,
            current_app:Option<Identity>,complete:bool,
        }
        impl RemovalRemainingPlan {
            fn new(book:&Install,source:&worker::RemovalResumeSource,base:u64)->Result<Self> {
                source.authenticated_selection(book)?;
                check(base>=book.removal_control_reserved && base<=16*1024*1024,"removal-resume-plan-budget")?;
                let plan=Self {nodes:Vec::new(),generations:Vec::new(),stack:[None;17],active:None,base,transient:0,
                    expected_files:0,present_files:0,present_bytes:0,expected_directories:0,current_app:None,complete:false};plan.memory(0)?;Ok(plan)
            }
            fn begin_generation(&mut self,generation:&GenerationData,index:&installation_record::InventoryIndex<'_>)->Result<()> {
                check(!self.complete && self.active.is_none() && self.stack.iter().all(Option::is_none)
                    && self.generations.len()<9,"removal-resume-generation-once")?;
                let binding=generation.release_data().binding_data();
                let current=generation.retained_invocation_data().is_none();
                check(current==self.generations.is_empty() && !self.generations.iter().any(|g|g.release==binding.release),
                    "removal-resume-generation-order")?;
                let app_name=if current{"app".to_owned()}else{data(transaction::retained_app_name_data(
                    generation.retained_invocation_data().ok_or("removal-resume-generation-retained")?))?};
                self.memory(9*std::mem::size_of::<RemovalRemainingGeneration>()+binding.release.len()+64+app_name.capacity())?;
                if self.generations.capacity()==0{self.generations.try_reserve_exact(9).map_err(|_|"removal-resume-plan-allocation")?;}
                check(self.generations.capacity()<=9,"removal-resume-plan-allocation")?;
                self.active=Some(self.generations.len());self.generations.push(RemovalRemainingGeneration {
                    release:binding.release.into(),inventory:binding.inventory_sha256.into(),app_name,current});
                self.expected_files=self.expected_files.checked_add(index.files.len() as u64).ok_or("removal-resume-plan-count")?;
                self.expected_directories=self.expected_directories.checked_add(index.directories.len() as u64).ok_or("removal-resume-plan-count")?;
                self.memory(0)
            }
            fn end_generation(&mut self)->Result<()> {
                check(self.active.take().is_some() && self.stack.iter().all(Option::is_none),"removal-resume-generation-incomplete")
            }
            pub(super) fn payload_all_absent_data(&self)->bool {
                self.complete && self.current_app.is_none() && self.nodes.iter().all(|row|matches!(row.presence,RemovalRemainingPresence::Absent{..}))
            }
            pub(super) fn payload_presence_data(&self)->mobile_release_desktop::macos_remove_record::PayloadPresenceData {
                use mobile_release_desktop::macos_remove_record::PayloadPresenceData as P;
                if !self.complete {P::Unknown}else if self.payload_all_absent_data(){P::AllAbsent}
                else if self.present_files==self.expected_files && self.nodes.iter().all(|row|matches!(row.presence,RemovalRemainingPresence::Present{..}))
                    {P::AllPresentMatching}else{P::PartialInRosterMatching}
            }
            pub(super) fn app_slots_data(&self)->mobile_release_desktop::macos_remove_record::AppSlotsData {
                use mobile_release_desktop::macos_remove_record::AppSlotsData as A;
                if !self.complete{A::Unknown}else if self.current_app.is_some(){A::NewOnly}else{A::Neither}
            }
            pub(super) fn fingerprint_data(&self)->Result<[u8;32]>{self.fingerprint()}
            fn owned_bytes(&self,extra:usize)->Result<usize> {
                let bytes=self.nodes.capacity().checked_mul(std::mem::size_of::<RemovalRemainingNode>())
                    .and_then(|n|n.checked_add(self.generations.capacity().checked_mul(std::mem::size_of::<RemovalRemainingGeneration>())?))
                    .and_then(|n|n.checked_add(std::mem::size_of::<Self>()+self.transient))
                    .and_then(|n|n.checked_add(extra)).ok_or("removal-resume-plan-memory")?;
                let mut bytes=bytes;
                for row in &self.nodes{bytes=bytes.checked_add(row.path.capacity()).ok_or("removal-resume-plan-memory")?;}
                for row in &self.generations{bytes=bytes.checked_add(row.release.capacity()+row.inventory.capacity()+row.app_name.capacity())
                    .ok_or("removal-resume-plan-memory")?;}
                Ok(bytes)
            }
            fn memory(&self,extra:usize)->Result<()> {
                check(self.base.checked_add(self.owned_bytes(extra)? as u64).is_some_and(|n|n<=16*1024*1024),"removal-resume-plan-memory")
            }
            fn push(&mut self,path:&str,directory:bool,size:u64,digest:[u8;32],executable:bool,
                presence:RemovalRemainingPresence,depth:usize)->Result<usize> {
                check(!self.complete && self.active.is_some() && depth<=17 && path.len()<=1024
                    && self.nodes.len()<REMOVAL_PLAN_NODES,"removal-resume-plan-shape")?;
                if self.nodes.len()==self.nodes.capacity(){
                    let old=self.nodes.capacity();let next=old.max(16).checked_mul(2).ok_or("removal-resume-plan-count")?.min(REMOVAL_PLAN_NODES);
                    // Count both old/new allocations during reserve, then the
                    // actual retained capacity. No capacity or original reset.
                    self.memory(next*std::mem::size_of::<RemovalRemainingNode>()+path.len())?;
                    self.nodes.try_reserve_exact(next-self.nodes.len()).map_err(|_|"removal-resume-plan-allocation")?;
                    check(self.nodes.capacity()<=next,"removal-resume-plan-allocation")?;
                }
                self.memory(path.len())?;let path=path.to_owned();
                check(path.capacity()<=1024,"removal-resume-plan-allocation")?;
                let parent=if depth==0{None}else{self.stack[depth-1]};
                check(depth==0 || parent.is_some(),"removal-resume-plan-parent")?;
                let index=self.nodes.len();self.nodes.push(RemovalRemainingNode {generation:self.active.ok_or("removal-resume-plan-generation")?,
                    path,parent,directory,size,digest,executable,presence});self.memory(0)?;Ok(index)
            }
            fn enter(&mut self,book:&Install,root:usize,path:&str,depth:usize)->Result<()> {
                check(depth<17 && self.stack[depth].is_none(),"removal-resume-plan-depth")?;
                let actual=stat::fstat(book.fd(root)?).map_err(|_|"removal-resume-plan-stat")?;
                check(Identity::of(&actual)==book.identity(root)? && actual.st_flags==0,"removal-resume-plan-original")?;
                let index=self.push(path,true,0,[0;32],false,RemovalRemainingPresence::Present{identity:Identity::of(&actual),flags:0},depth)?;
                self.stack[depth]=Some(index);Ok(())
            }
            fn leave(&mut self,depth:usize)->Result<()> {
                check(depth<17 && self.stack[depth].take().is_some() && self.stack[depth+1..].iter().all(Option::is_none),
                    "removal-resume-plan-depth")
            }
            fn file(&mut self,book:&Install,n:usize,path:&str,entry:&installation_record::Entry,depth:usize)->Result<()> {
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-resume-plan-stat")?;
                check(Identity::of(&actual)==book.identity(n)? && actual.st_flags==0,"removal-resume-plan-original")?;
                self.push(path,false,entry.size,worker::removal_hex_data::<32>(&entry.sha256)?,entry.executable,
                    RemovalRemainingPresence::Present{identity:Identity::of(&actual),flags:0},depth)?;
                self.present_files=self.present_files.checked_add(1).ok_or("removal-resume-plan-count")?;
                self.present_bytes=self.present_bytes.checked_add(entry.size).ok_or("removal-resume-plan-count")?;Ok(())
            }
            fn absent(&mut self,book:&Install,parent:usize,name:&str,path:&str,directory:bool,
                entry:Option<&installation_record::Entry>,depth:usize)->Result<()> {
                book.check_name(parent,true)?;book.absent(parent,name)?;book.check_name(parent,true)?;
                let (size,digest,executable)=if let Some(entry)=entry{(entry.size,worker::removal_hex_data::<32>(&entry.sha256)?,entry.executable)}
                    else{(0,[0;32],false)};
                self.push(path,directory,size,digest,executable,RemovalRemainingPresence::Absent{parent:book.identity(parent)?},depth)?;Ok(())
            }
            fn fingerprint(&self)->Result<[u8;32]> {
                check(self.complete && self.active.is_none() && self.stack.iter().all(Option::is_none),"removal-resume-plan-incomplete")?;
                let mut out=Sha256::new();out.update(b"MRK-REMOVAL-FRESH-OBSERVATION-V1\0");
                fn identity(out:&mut Sha256,id:Identity){
                    out.update(id.dev.to_le_bytes());out.update(id.ino.to_le_bytes());out.update(id.mode.to_le_bytes());
                    out.update(id.uid.to_le_bytes());out.update(id.gid.to_le_bytes());out.update(id.links.to_le_bytes());
                    out.update(id.size.to_le_bytes());out.update(id.mtime.to_le_bytes());out.update(id.mtime_ns.to_le_bytes());
                    out.update(id.ctime.to_le_bytes());out.update(id.ctime_ns.to_le_bytes());
                }
                for row in &self.generations {for text in [&row.release,&row.inventory,&row.app_name]{out.update((text.len() as u64).to_le_bytes());out.update(text.as_bytes());}
                    out.update([u8::from(row.current)]);}
                for row in &self.nodes {out.update((row.generation as u64).to_le_bytes());out.update((row.path.len() as u64).to_le_bytes());
                    out.update(row.path.as_bytes());out.update((row.parent.map(|n|n as u64).unwrap_or(u64::MAX)).to_le_bytes());
                    out.update([u8::from(row.directory),u8::from(row.executable)]);out.update(row.size.to_le_bytes());out.update(row.digest);
                    match row.presence {RemovalRemainingPresence::Present{identity:id,flags}=>{out.update([1]);identity(&mut out,id);out.update(flags.to_le_bytes());},
                        RemovalRemainingPresence::Absent{parent}=>{out.update([2]);identity(&mut out,parent);}}
                }
                out.update(self.expected_files.to_le_bytes());out.update(self.present_files.to_le_bytes());
                out.update(self.expected_directories.to_le_bytes());out.update(self.present_bytes.to_le_bytes());Ok(out.finalize().into())
            }
        }
        pub(super) struct RemovalSnapshotCapture {
            pub(super) root: usize, versions: Option<usize>, prior_archives:Option<RemovalArchiveCensus>, pub(super) controls: Vec<RemovalSnapshotControl>,
            directories: Vec<RemovalSnapshotDirectory>,
            pub(super) complete: bool, pub(super) quote: Option<(u64,u64)>,
            failed: bool,
        }
        pub(super) fn reserve_removal_snapshot_work(book:&mut Install)->Result<()> {
            if !book.removal_snapshot_work_reserved {
                let reserved=book.removal_control_reserved.checked_add(REMOVAL_SNAPSHOT_WORK)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-control-bound")?;
                book.removal_control_reserved=reserved;book.removal_snapshot_work_reserved=true;
            }
            check(book.removal_control_reserved>=REMOVAL_SNAPSHOT_WORK && book.removal_control_reserved<=16*1024*1024,
                "removal-control-bound")
        }
        fn snapshot_path(book:&Install,root:usize,mut original:usize)->Result<String> {
            if original==root { return Ok(String::new()); }
            let mut parts=Vec::new();
            for _ in 0..3 {
                let value=book.originals.get(original).ok_or("removal-snapshot-location")?;
                check(component(&value.name) && value.name.len()<=255,"removal-snapshot-location")?;
                parts.push(value.name.as_str());
                original=value.parent.ok_or("removal-snapshot-location")?;
                if original==root {
                    parts.reverse();let path=parts.join("/");
                    check(path.len()<=1024,"removal-snapshot-location")?;return Ok(path);
                }
            }
            Err("removal-snapshot-location")
        }
        fn snapshot_stat(book:&Install,original:usize)->Result<(Identity,u32)> {
            book.check_name(original,true)?;
            let actual=stat::fstat(book.fd(original)?).map_err(|_|"removal-snapshot-stat")?;
            check(Identity::of(&actual)==book.identity(original)?,"removal-snapshot-original")?;
            Ok((Identity::of(&actual),actual.st_flags))
        }
        impl RemovalSnapshotCapture {
            pub(super) fn begin(book:&mut Install,root:usize)->Result<()> {
                check(book.removal_snapshot_capture.is_none(),"removal-snapshot-once")?;
                reserve_removal_snapshot_work(book)?;
                let mut controls=Vec::new();let mut directories=Vec::new();
                controls.try_reserve_exact(SNAPSHOT_CONTROLS).map_err(|_|"removal-snapshot-allocation")?;
                directories.try_reserve_exact(SNAPSHOT_DIRECTORIES).map_err(|_|"removal-snapshot-allocation")?;
                let value=Self { root,versions:None,prior_archives:None,controls,directories,complete:false,quote:None,failed:false };
                value.memory(0)?;book.removal_snapshot_capture=Some(value);Ok(())
            }
            pub(super) fn memory(&self,extra:usize)->Result<usize> {
                let mut total=std::mem::size_of::<Self>()
                    .checked_add(self.controls.capacity().checked_mul(std::mem::size_of::<RemovalSnapshotControl>()).ok_or("removal-snapshot-memory")?)
                    .and_then(|n|n.checked_add(self.directories.capacity()*std::mem::size_of::<RemovalSnapshotDirectory>()))
                    .and_then(|n|n.checked_add(extra)).ok_or("removal-snapshot-memory")?;
                for row in &self.controls { total=total.checked_add(row.path.capacity()).ok_or("removal-snapshot-memory")?; }
                for row in &self.directories {
                    total=total.checked_add(row.path.capacity()).and_then(|n|n.checked_add(row.children.capacity()*std::mem::size_of::<(String,u64)>()))
                        .ok_or("removal-snapshot-memory")?;
                    for (name,_) in &row.children { total=total.checked_add(name.capacity()).ok_or("removal-snapshot-memory")?; }
                }
                // The separately bounded first/second shallow census tables
                // can overlap during this same second observation. Their old
                // table is dropped before finish moves the completed second.
                if !self.complete { total=total.checked_add(256*1024).ok_or("removal-snapshot-memory")?; }
                if let Some(prior)=&self.prior_archives {
                    total=total.checked_add(prior.owned_bytes().map_err(|_|"removal-snapshot-memory")?).ok_or("removal-snapshot-memory")?;
                }
                // Includes copy/readback blocks, bounded admission codec copies,
                // fixed frame data and all header capacity supplied by caller.
                total=total.checked_add(256*1024).ok_or("removal-snapshot-memory")?;
                check(total as u64<=REMOVAL_SNAPSHOT_WORK,"removal-snapshot-memory")?;Ok(total)
            }
            fn add(&mut self,row:RemovalSnapshotControl)->Result<()> {
                check(!self.failed,"removal-snapshot-refused")?;
                if let Some(old)=self.controls.iter_mut().find(|old|old.path==row.path) {
                    check(removal_snapshot_control_equal_data(old,&row),"removal-snapshot-duplicate")?;
                    if let Some(held)=row.held { old.held=Some(held); }
                } else {
                    check(self.controls.len()<SNAPSHOT_CONTROLS && row.path.len()<=1024
                        && row.size>0 && row.size<=installation_record::INVENTORY_LIMIT as u64,
                        "removal-snapshot-control-bound")?;
                    self.memory(row.path.capacity())?;self.controls.push(row);
                }
                self.memory(0)?;Ok(())
            }
            pub(super) fn held(&mut self,book:&Install,original:usize,raw:&[u8],kind:u8)->Result<()> {
                check(self.complete && !self.failed && kind<=4,"removal-snapshot-held")?;
                held_bytes(book,original,raw)?;
                let (identity,flags)=snapshot_stat(book,original)?;
                let path=match kind { 1=>"@remove/producer.json".to_owned(),2=>"@remove/producer.sig".to_owned(),
                    _=>snapshot_path(book,self.root,original)? };
                self.add(RemovalSnapshotControl { path,identity,flags,size:raw.len() as u64,
                    digest:Sha256::digest(raw).into(),kind,held:Some(original) })
            }
            pub(super) fn finish(&mut self,prior:RemovalArchiveCensus)->Result<()> {
                check(!self.failed && !self.complete && self.quote.is_some()
                    && self.directories.iter().any(|d|d.path.is_empty()),"removal-snapshot-capture-incomplete")?;
                check(prior.rows().len()<=64 && prior.storage_bytes()<=installation_record::PAYLOAD_LIMIT,"removal-snapshot-prior-bound")?;
                self.memory(prior.owned_bytes().map_err(|_|"removal-snapshot-memory")?)?;
                self.prior_archives=Some(prior);
                self.controls.sort_by(|a,b|a.path.cmp(&b.path));
                self.directories.sort_by(|a,b|a.path.cmp(&b.path));
                self.complete=true;self.memory(0)?;Ok(())
            }
            pub(super) fn root_children(&self)->Result<&[(String,u64)]> {
                self.directories.iter().find(|d|d.path.is_empty()).map(|d|d.children.as_slice())
                    .ok_or("removal-snapshot-root-census")
            }
            pub(super) fn directory_count(&self)->usize { self.directories.len() }
            pub(super) fn prior_archives(&self)->Result<&RemovalArchiveCensus> { self.prior_archives.as_ref().ok_or("removal-snapshot-prior-missing") }
            pub(super) fn directory_identity(&self,path:&str)->Result<(Identity,u32)> {
                self.directories.iter().find(|d|d.path==path).map(|d|(d.identity,d.flags))
                    .ok_or("removal-snapshot-directory-census")
            }
            pub(super) fn header(&self,request:&mobile_release_desktop::macos_remove_protocol::BindingData,
                state_sha:&str,selected:&[u8],working_extra:usize)->Result<Vec<u8>> {
                check(self.complete && !self.failed && !selected.is_empty()
                    && selected.len()<=mobile_release_desktop::macos_install_maintenance::INPUT_LIMIT,
                    "removal-snapshot-header")?;
                let fields=request.fields_data();
                let base=self.memory(working_extra)?;
                let allowance=(REMOVAL_SNAPSHOT_WORK as usize).checked_sub(base).ok_or("removal-snapshot-memory")?;
                let mut out=SnapshotBytes::new(allowance.min(SNAPSHOT_HEADER))?;
                out.put(REMOVAL_SNAPSHOT_MAGIC)?;
                out.put(&[match fields.target { mobile_release_desktop::macos_remove_protocol::TargetData::Arm64=>1,
                    mobile_release_desktop::macos_remove_protocol::TargetData::Intel=>2 }])?;
                for value in [fields.request_id,fields.root_nonce,fields.source_commit,state_sha,
                    fields.installed_producer_sha256,fields.installed_inventory_sha256,fields.remove_producer_sha256] { out.string(value)?; }
                out.u32(selected.len())?;out.put(selected)?;
                out.u16(self.directories.len())?;
                for row in &self.directories {
                    out.string(&row.path)?;out.identity(row.identity,row.flags)?;out.u16(row.children.len())?;
                    for (name,inode) in &row.children { out.string(name)?;out.put(&inode.to_be_bytes())?; }
                }
                let prior=self.prior_archives()?;out.u16(prior.rows().len())?;
                let mut previous=None;let mut prior_bytes=0u64;
                for row in prior.rows() {
                    check(worker::removal_archive_name_data(row.name()) && previous.is_none_or(|old:&str|old<row.name()),"removal-snapshot-prior-order")?;
                    previous=Some(row.name());out.string(row.name())?;out.identity(row.identity(),row.flags())?;
                    for file in row.files() {
                        if let Some(file)=file {
                            check(matches!(file.shape_tag_data(),1|2) && file.identity().size>=0
                                && file.len()==file.identity().size as u64,"removal-snapshot-prior-shape")?;
                            prior_bytes=prior_bytes.checked_add(file.len()).ok_or("removal-snapshot-prior-bound")?;
                            out.put(&[1])?;out.identity(file.identity(),file.flags())?;
                            out.put(&file.len().to_be_bytes())?;out.put(file.digest())?;out.put(&[file.shape_tag_data()])?;
                        } else { out.put(&[0])?; }
                    }
                    // Named nofollow comparison only; no recursive body or
                    // old app-original authority is carried by this marker.
                    if let Some((identity,flags))=row.app_data() {out.put(&[1])?;out.identity(identity,flags)?;}
                    else {out.put(&[0])?;}
                }
                check(prior_bytes==prior.storage_bytes(),"removal-snapshot-prior-bound")?;
                out.u16(self.controls.len())?;
                self.memory(out.0.capacity()+working_extra)?;Ok(out.0)
            }
        }
        // Fixed DATA encoder only: no IO, original ownership or general writer.
        struct SnapshotBytes(Vec<u8>,usize);
        impl SnapshotBytes {
            fn new(limit:usize)->Result<Self> {
                let mut bytes=Vec::new();bytes.try_reserve_exact(limit).map_err(|_|"removal-snapshot-allocation")?;
                check(bytes.capacity()<=limit,"removal-snapshot-header-bound")?;Ok(Self(bytes,limit))
            }
            fn put(&mut self,value:&[u8])->Result<()> {
                let total=self.0.len().checked_add(value.len()).filter(|n|*n<=self.1)
                    .ok_or("removal-snapshot-header-bound")?;
                // One precharged allocation: no old/new buffer growth overlap.
                check(total<=self.0.capacity(),"removal-snapshot-header-bound")?;
                self.0.extend_from_slice(value);Ok(())
            }
            fn u16(&mut self,value:usize)->Result<()> { self.put(&u16::try_from(value).map_err(|_|"removal-snapshot-count")?.to_be_bytes()) }
            fn u32(&mut self,value:usize)->Result<()> { self.put(&u32::try_from(value).map_err(|_|"removal-snapshot-count")?.to_be_bytes()) }
            fn string(&mut self,value:&str)->Result<()> { check(value.len()<=1024,"removal-snapshot-string")?;self.u16(value.len())?;self.put(value.as_bytes()) }
            fn identity(&mut self,id:Identity,flags:u32)->Result<()> {
                self.put(&id.dev.to_be_bytes())?;self.put(&id.ino.to_be_bytes())?;
                for value in [id.mode,id.uid,id.gid,flags] { self.put(&value.to_be_bytes())?; }
                self.put(&id.links.to_be_bytes())?;
                for value in [id.size,id.mtime,id.mtime_ns,id.ctime,id.ctime_ns] { self.put(&value.to_be_bytes())?; } Ok(())
            }
        }
        pub(super) fn removal_snapshot_control_equal_data(a:&RemovalSnapshotControl,b:&RemovalSnapshotControl)->bool {
            a.path==b.path && a.identity==b.identity && a.flags==b.flags && a.size==b.size && a.digest==b.digest && a.kind==b.kind
        }
        pub(super) fn removal_snapshot_frame_data(row:&RemovalSnapshotControl)->Result<Vec<u8>> {
            check(row.kind<=4 && !row.path.is_empty() && row.size>0
                && row.size<=installation_record::INVENTORY_LIMIT as u64,"removal-snapshot-frame")?;
            let mut out=SnapshotBytes::new(2048)?;out.put(&[row.kind])?;out.string(&row.path)?;
            out.identity(row.identity,row.flags)?;out.put(&row.size.to_be_bytes())?;out.put(&row.digest)?;Ok(out.0)
        }
        fn removal_snapshot_metadata(book:&mut Install,reader:usize,raw:&[u8])->Result<()> {
            let Some(mut capture)=book.removal_snapshot_capture.take() else { return Ok(()); };
            let result=(|| {
                check(!capture.complete && !capture.failed,"removal-snapshot-capture-phase")?;
                let (identity,flags)=snapshot_stat(book,reader)?;
                let path=snapshot_path(book,capture.root,reader)?;
                capture.add(RemovalSnapshotControl { path,identity,flags,size:raw.len() as u64,
                    digest:Sha256::digest(raw).into(),kind:0,held:None })
            })();
            if result.is_err() { capture.failed=true; }
            book.removal_snapshot_capture=Some(capture);result
        }
        pub(super) fn removal_snapshot_child_data(root:bool,name:&str,inode:u64)->bool {
            inode!=0 && name.len()<=255 && (component(name) || root && name==paths::APP_NAME)
        }
        fn removal_snapshot_roster(book:&mut Install,directory:usize,actual:&BTreeMap<String,u64>)->Result<()> {
            let Some(mut capture)=book.removal_snapshot_capture.take() else { return Ok(()); };
            let result=(|| {
                check(!capture.complete && !capture.failed,"removal-snapshot-capture-phase")?;
                let path=snapshot_path(book,capture.root,directory)?;
                if path=="versions" { capture.versions=Some(directory); }
                let (identity,flags)=snapshot_stat(book,directory)?;
                if let Some(old)=capture.directories.iter().find(|row|row.path==path) {
                    return check(old.identity==identity && old.flags==flags && old.children.len()==actual.len() && old.children.iter().all(|(n,i)|actual.get(n)==Some(i)),
                        "removal-snapshot-directory-duplicate");
                }
                let count=capture.directories.iter().map(|row|row.children.len()).sum::<usize>();
                check(capture.directories.len()<SNAPSHOT_DIRECTORIES && count.checked_add(actual.len()).is_some_and(|n|n<=SNAPSHOT_CHILDREN),
                    "removal-snapshot-directory-bound")?;
                check(actual.iter().all(|(n,i)|removal_snapshot_child_data(path.is_empty(),n,*i)),"removal-snapshot-child")?;
                let projected=path.capacity()+actual.len()*(std::mem::size_of::<(String,u64)>()+255);
                capture.memory(projected)?;
                let children=actual.iter().map(|(n,i)|(n.clone(),*i)).collect();
                capture.directories.push(RemovalSnapshotDirectory { path,identity,flags,children });capture.memory(0)?;Ok(())
            })();
            if result.is_err() { capture.failed=true; }
            book.removal_snapshot_capture=Some(capture);result
        }
        impl RemovalObserved {
            pub(super) fn snapshot_state_bytes(&self)->Result<&[u8]> {
                self.inner.history.as_ref().map(|h|h.state_bytes.as_slice()).ok_or("removal-snapshot-state")
            }
        }
        impl RemovalSnapshotCapture {
            pub(super) fn versions_original(&self)->Result<usize> { self.versions.ok_or("removal-snapshot-versions") }
            pub(super) fn census_post(&self,book:&mut Install,archive:&str,inode:u64)->Result<()> {
                check(self.complete && !self.failed,"removal-snapshot-capture-incomplete")?;
                for row in &self.directories {
                    let n=if row.path.is_empty() {
                        let source=&book.originals[self.root];let parent=source.parent;let name=source.name.clone();
                        book.open(parent,&name,true)?
                    } else {
                        let (parent,name)=match row.path.split_once('/') {
                            None=>(self.root,row.path.as_str()),
                            Some(("versions",name)) if !name.contains('/') => (self.versions_original()?,name),
                            _=>return Err("removal-snapshot-directory-location"),
                        };
                        book.open(Some(parent),name,true)?
                    };
                    let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-census-stat")?;
                    let expected=if row.path.is_empty() {book.identity(self.root)?}else{row.identity};
                    check(Identity::of(&actual)==expected && actual.st_flags==row.flags,"removal-snapshot-census-original")?;
                    book.protected(n,true,Some(if row.path.starts_with(".install-"){0o700}else{0o755}))?;
                    native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-snapshot-census-attributes")?;
                    let actual=book.roster(n)?;
                    check(if row.path.is_empty() { worker::removal_snapshot_root_delta_data(&row.children,&actual,archive,inode) }
                        else { actual.len()==row.children.len() && row.children.iter().all(|(name,inode)|actual.get(name)==Some(inode)) },
                        "removal-snapshot-census-changed")?;
                    book.check_name(n,true)?;book.forward_close(n,"removal-snapshot-census-close")?;
                }
                Ok(())
            }
        }

        impl RemovalSnapshotCapture {
            pub(super) fn directory_children(&self,path:&str)->Result<&[(String,u64)]> {
                self.directories.iter().find(|r|r.path==path).map(|r|r.children.as_slice()).ok_or("removal-payload-control-directory")
            }
            pub(super) fn directory_rows_data(&self)->impl Iterator<Item=(&str,Identity,u32,&[(String,u64)])> {
                self.directories.iter().map(|r|(r.path.as_str(),r.identity,r.flags,r.children.as_slice()))
            }
        }
        impl RemovalObserved {
            // Only immutable controls survive code withdrawal. This is not the
            // old full app/source POST with its missing-name checks suppressed.
            pub(super) fn payload_controls_post(&self,book:&Install)->Result<()> {
                held_inventory(book,self.inventory_original,self.inventory_bytes())?;
                held_bytes(book,self.record_original,&self.record_bytes)?;
                self.inner.controls_post(book)?;
                let history=self.inner.history.as_ref().ok_or("removal-payload-state")?;
                held_bytes(book,history.state_original,&history.state_bytes)
            }
        }
        pub(super) fn rebind_removal_app(book:&mut Install,original:usize,archive:usize)->Result<()> {
            rebind_renamed(book,original,archive,"app")
        }

        // Each additional observation acquires and accounts its own descriptor;
        // it is not adoption of a failed or retired descriptor, nor an offset reset.
        pub(super) fn roster_now(book: &mut Install, directory: usize) -> Result<BTreeMap<String, u64>> {
            book.check_name(directory, false)?;
            let parent = book.originals[directory].parent;
            let name = book.originals[directory].name.clone();
            let reader = book.open(parent, &name, true)?;
            check(book.identity(directory)?.same_object(book.identity(reader)?), "maintenance-roster-original")?;
            let values = book.roster(reader)?;
            book.check_name(reader, true)?;
            book.forward_close(reader, "maintenance-roster-close")?;
            book.check_name(directory, false)?; Ok(values)
        }
        fn exact_roster(book: &mut Install, directory: usize, wanted: &BTreeSet<String>) -> Result<()> {
            let actual=roster_now(book,directory)?;
            check(actual.keys().cloned().collect::<BTreeSet<_>>() == *wanted,"maintenance-exact-roster")?;
            removal_snapshot_roster(book,directory,&actual)
        }
        pub(super) fn fresh_registration_roster(book: &mut Install, root: usize, versions: usize) -> Result<()> {
            check(book.gate.verified && book.gate.exclusive_acquired && !book.worker_stderr_is_gate,
                "registration-maintenance-required")?;
            let mut names: BTreeSet<String> = ["versions", paths::MAINTENANCE_GATE_NAME].into_iter().map(str::to_owned).collect();
            if book.registration.verified { names.insert(paths::REGISTRATION_GATE_NAME.into()); }
            exact_roster(book, root, &names)?; exact_roster(book, versions, &BTreeSet::new())
        }
        pub(super) fn metadata_original(book: &mut Install, parent: usize, name: &str, limit: usize) -> Result<(usize, Vec<u8>)> {
            let reader = book.open(Some(parent), name, false)?;
            book.protected(reader, false, Some(0o444))?;
            native::no_xattrs(book.fd(reader)?.as_fd()).map_err(|_| "maintenance-record-attributes")?;
            let original = stat::fstat(book.fd(reader)?).map_err(|_| "maintenance-record-stat")?;
            let size = usize::try_from(original.st_size).map_err(|_| "maintenance-record-size")?;
            check(original.st_flags == 0 && size > 0 && size <= limit, "maintenance-record-size")?;
            let bytes = book.read(reader, size as u64, true)?.1;
            let post = stat::fstat(book.fd(reader)?).map_err(|_| "maintenance-record-stat")?;
            check(post.st_flags == 0 && Identity::of(&post) == book.identity(reader)?, "maintenance-record-post")?;
            removal_snapshot_metadata(book,reader,&bytes)?;
            Ok((reader, bytes))
        }
        fn metadata_bytes(book: &mut Install, parent: usize, name: &str, limit: usize) -> Result<Vec<u8>> {
            let (reader, bytes) = metadata_original(book, parent, name, limit)?;
            book.forward_close(reader, "maintenance-record-close")?; Ok(bytes)
        }
        fn control_names(selected: &ReleaseSetData, release: &str) -> Result<(String,String)> {
            mobile_release_desktop::macos_install_producer::installed_control_names_data(selected.target_data(),release)
                .map_err(|_| "maintenance-producer-name")
        }
        fn generation_controls(book: &mut Install, root: usize, generation: &GenerationData,
            selected: &ReleaseSetData, root_names: &mut BTreeSet<String>, keep: bool) -> Result<(Option<ProducerControls>,u64)> {
            use mobile_release_desktop::macos_install_producer as producer;
            let names = control_names(selected,generation.release_data().binding_data().release)?;
            check(root_names.insert(names.0.clone()) && root_names.insert(names.1.clone()),"maintenance-producer-name-reused")?;
            let (descriptor, descriptor_bytes) = metadata_original(book,root,&names.0,producer::DESCRIPTOR_LIMIT)?;
            let (signature, signature_bytes) = metadata_original(book,root,&names.1,producer::SIGNATURE_LIMIT)?;
            // Parsing an old descriptor checks only correspondence with an
            // independently accepted old tuple; it is not old signer/finality
            // authority. The incoming current pair is additionally compared to
            // its actual authenticated source bytes before GO.
            let parsed = producer::ProducerData::parse_data(&descriptor_bytes,selected.target_data())
                .map_err(|_| "maintenance-producer-record")?;
            check(parsed.release_set_data().current_data() == generation.release_data(),"maintenance-producer-generation")?;
            let count = (descriptor_bytes.len() + signature_bytes.len()) as u64;
            let pair = ProducerControls { originals:[descriptor,signature],bytes:[descriptor_bytes,signature_bytes] };
            pair.post(book)?;
            if keep { Ok((Some(pair),count)) } else {
                for original in pair.originals { book.forward_close(original,"maintenance-producer-close")?; }
                Ok((None,count))
            }
        }
        // Bounded positional read on the SAME held original. Unlike read(), this
        // does not depend on a previously consumed offset or mutate a shared OFD.
        pub(super) fn held_bytes(book: &Install, reader: usize, expected: &[u8]) -> Result<()> {
            held_bytes_bounded(book,reader,expected,transaction::CAPSULE_LIMIT)
        }
        fn held_inventory(book: &Install, reader: usize, expected: &[u8]) -> Result<()> {
            held_bytes_bounded(book,reader,expected,installation_record::INVENTORY_LIMIT)
        }
        fn held_bytes_bounded(book: &Install, reader: usize, expected: &[u8], limit: usize) -> Result<()> {
            check(!expected.is_empty() && expected.len() <= limit, "maintenance-record-size")?;
            book.check_name(reader, true)?;
            check(book.identity(reader)?.size == expected.len() as i64, "maintenance-record-size")?;
            let mut at: usize = 0; let mut block = [0u8;4096];
            loop {
                book.clock()?;
                let count = nix::sys::uio::pread(book.fd(reader)?, &mut block, at as i64)
                    .map_err(|_| "maintenance-record-read")?;
                if count == 0 { break; }
                check(count <= block.len() && at.checked_add(count).is_some_and(|n| n <= expected.len())
                    && block[..count] == expected[at..at+count], "maintenance-record-content")?;
                at += count;
            }
            check(at == expected.len(), "maintenance-record-size")?; book.check_name(reader, true)
        }
        fn recorded(book: &mut Install, root: usize, invocation: &str, state: StateData,
            selected: &ReleaseSetData, bytes: &mut u64) -> Result<Recorded> {
            check(state.invocation_data() == invocation && state.mutation_recorded_data(), "maintenance-history-state")?;
            let intent_bytes = metadata_bytes(book, root, &data(transaction::intent_name_data(invocation))?, transaction::INTENT_LIMIT)?;
            let capsule_bytes = metadata_bytes(book, root, &data(transaction::capsule_name_data(invocation))?, transaction::CAPSULE_LIMIT)?;
            *bytes = bytes.checked_add((intent_bytes.len() + capsule_bytes.len()) as u64).ok_or("maintenance-control-bound")?;
            let intent = data(IntentData::parse_recorded_data(&intent_bytes, selected))?;
            let capsule = data(CapsuleData::parse_recorded_data(&capsule_bytes, selected))?;
            check(intent.invocation_data() == invocation && capsule.invocation_data() == invocation,
                "maintenance-history-invocation")?;
            Ok(Recorded { intent, state, capsule })
        }
        fn previous<'a>(record: &Recorded, history: &'a BTreeMap<String, Recorded>) -> Result<Option<(&'a StateData, &'a CapsuleData)>> {
            match record.intent.previous_state_data() {
                None => Ok(None),
                Some((invocation, digest)) => {
                    let old = history.get(invocation).ok_or("maintenance-history-missing")?;
                    check(old.state.digest_data() == digest, "maintenance-history-binding")?;
                    Ok(Some((&old.state, &old.capsule)))
                }
            }
        }
        fn read_history(book: &mut Install, root: usize, selected: &ReleaseSetData) -> Result<History> {
            let (state_original, current_bytes) = metadata_original(book, root, transaction::STATE_NAME, transaction::STATE_LIMIT)?;
            let state = data(StateData::parse_data(&current_bytes, selected))?;
            check(state.mutation_recorded_data(), "maintenance-history-pending")?;
            let refs: Vec<_> = state.evidence_data().map(|item| (item.invocation.to_owned(), item.intent_sha256.to_owned(),
                item.state_sha256.to_owned(), item.capsule_sha256.to_owned())).collect();
            let invocation = state.invocation_data().to_owned();
            let mut bytes = current_bytes.len() as u64;
            let current = recorded(book, root, &invocation, state, selected, &mut bytes)?;
            let mut originals = BTreeMap::new();
            for (invocation, intent_sha, state_sha, capsule_sha) in refs {
                let archived = metadata_bytes(book, root, &data(transaction::archived_state_name_data(&invocation))?, transaction::STATE_LIMIT)?;
                bytes = bytes.checked_add(archived.len() as u64).ok_or("maintenance-control-bound")?;
                check(hash(&archived) == state_sha, "maintenance-history-binding")?;
                let record = recorded(book, root, &invocation, data(StateData::parse_data(&archived, selected))?, selected, &mut bytes)?;
                check(record.intent.digest_data() == intent_sha && record.capsule.digest_data() == capsule_sha
                    && originals.insert(invocation, record).is_none(), "maintenance-history-binding")?;
            }
            let mut requests = BTreeSet::new();
            for record in originals.values().chain(std::iter::once(&current)) {
                check(requests.insert(record.intent.request_id_data()), "maintenance-request-reused")?;
                check(transaction::correspondence_data(&record.intent, previous(record, &originals)?,
                    Some(&record.state), Some(&record.capsule)) == CorrespondenceData::MatchingRecordedData,
                    "maintenance-history-correspondence")?;
            }
            held_bytes(book, state_original, &current_bytes)?;
            Ok(History { current, originals, state_original, state_bytes:current_bytes, bytes })
        }
        fn app_identity(book: &Install, original: usize) -> Result<AppIdentityData> {
            book.check_name(original, true)?; book.protected(original, true, Some(0o555))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "maintenance-app-attributes")?;
            let stat = stat::fstat(book.fd(original)?).map_err(|_| "maintenance-app-stat")?;
            data(AppIdentityData::from_original_fields_data(i64::from(stat.st_dev), stat.st_ino,
                u32::from(stat.st_mode), stat.st_uid, stat.st_gid, stat.st_flags))
        }
        fn audit_tree(book: &mut Install, root: usize, prefix: &str, index: &installation_record::InventoryIndex<'_>, depth: usize) -> Result<()> {
            audit_tree_mode(book,root,prefix,index,depth,None)
        }
        fn audit_tree_mode(book:&mut Install,root:usize,prefix:&str,index:&installation_record::InventoryIndex<'_>,depth:usize,
            mut resume:Option<&mut RemovalRemainingPlan>)->Result<()> {
            check(depth <= 16, "maintenance-tree-depth")?;
            book.protected(root, true, Some(0o555))?;
            native::no_xattrs(book.fd(root)?.as_fd()).map_err(|_| "maintenance-payload-attributes")?;
            check(stat::fstat(book.fd(root)?).map_err(|_| "maintenance-payload-stat")?.st_flags == 0,
                "maintenance-payload-flags")?;
            let wanted: BTreeSet<String> = index.files.keys().chain(index.directories.iter()).filter_map(|name|
                name.rsplit_once('/').filter(|(parent,_)| *parent == prefix).map(|(_,leaf)| leaf.to_owned())).collect();
            let actual = roster_now(book, root)?;
            if let Some(plan)=resume.as_deref_mut() {
                check(removal_resume_children_data(&wanted,&actual),"removal-resume-foreign-payload")?;
                plan.enter(book,root,prefix,depth)?;
            }else{
                check(actual.keys().cloned().collect::<BTreeSet<_>>() == wanted, "maintenance-payload-roster")?;
                payload_directory_enter(book,root,prefix,depth,actual.len())?;
            }
            for name in wanted {
                let path = format!("{prefix}/{name}");
                if let Some(plan)=resume.as_deref_mut(){if !actual.contains_key(&name){
                    let entry=index.files.get(&path).copied();
                    plan.absent(book,root,&name,&path,entry.is_none(),entry,depth+1)?;continue;
                }}
                if let Some(entry) = index.files.get(&path) {
                    let reader = book.open(Some(root), &name, false)?;
                    book.protected(reader, false, Some(if entry.executable { 0o555 } else { 0o444 }))?;
                    native::no_xattrs(book.fd(reader)?.as_fd()).map_err(|_| "maintenance-payload-attributes")?;
                    check(book.identity(reader)?.ino == actual[&name]
                        && stat::fstat(book.fd(reader)?).map_err(|_| "maintenance-payload-stat")?.st_flags == 0,
                        "maintenance-payload-original")?;
                    check(book.read(reader, entry.size, false)?.0 == entry.sha256, "maintenance-payload-hash")?;
                    if let Some(plan)=resume.as_deref_mut(){plan.file(book,reader,&path,entry,depth+1)?;}
                    else{payload_file_observed(book,reader,entry,depth)?;}
                    book.forward_close(reader, "maintenance-payload-close")?;
                } else {
                    let reader = book.open(Some(root), &name, true)?;
                    check(book.identity(reader)?.ino == actual[&name], "maintenance-payload-original")?;
                    audit_tree_mode(book,reader,&path,index,depth+1,resume.as_deref_mut())?;
                    book.forward_close(reader, "maintenance-payload-close")?;
                }
            }
            book.check_name(root,true)?;
            if let Some(plan)=resume {plan.leave(depth)}else{payload_directory_leave(book,depth)}
        }
        fn audit_generation(book: &mut Install, destination: usize, versions: usize, generation: &GenerationData,
            allow_missing_app: bool, keep: bool) -> Result<(Option<usize>, usize, GenerationCostData, u64)> {
            audit_generation_mode(book,destination,versions,generation,allow_missing_app,keep,None)
        }
        fn audit_generation_mode(book:&mut Install,destination:usize,versions:usize,generation:&GenerationData,
            allow_missing_app:bool,keep:bool,mut resume:Option<(&worker::RemovalResumeSource,&mut RemovalRemainingPlan)>)
            ->Result<(Option<usize>,usize,GenerationCostData,u64)> {
            let binding = generation.release_data().binding_data();
            let release = book.open(Some(versions), binding.release, true)?;
            check(book.recorded_directory(release)? == generation.release_directory_data(), "maintenance-release-original")?;
            let (raw,descriptor)=if let Some((source,_))=resume.as_ref() {
                // Bound the actual read by the already authenticated span,
                // BEFORE allocation; a replaced oversized control cannot spend
                // an inventory-limit allocation against a smaller quote.
                let inventory_path=format!("versions/{}/{}",binding.release,installation_record::INVENTORY_NAME);
                let record_path=format!("versions/{}/{}",binding.release,installation_record::RECORD_NAME);
                let inventory_span=source.genesis_control_data(book,&inventory_path)?;
                let record_span=source.genesis_control_data(book,&record_path)?;
                let inventory_limit=usize::try_from(inventory_span.len_data()).map_err(|_|"removal-resume-control-size")?;
                let record_limit=usize::try_from(record_span.len_data()).map_err(|_|"removal-resume-control-size")?;
                check(inventory_limit<=installation_record::INVENTORY_LIMIT && record_limit<=installation_record::RECORD_LIMIT,
                    "removal-resume-control-size")?;
                let raw=metadata_bytes(book,release,installation_record::INVENTORY_NAME,inventory_limit)?;
                let descriptor=metadata_bytes(book,release,installation_record::RECORD_NAME,record_limit)?;
                check(raw.len()==inventory_limit && descriptor.len()==record_limit
                    && <[u8;32]>::from(Sha256::digest(&raw))==*inventory_span.digest_data()
                    && <[u8;32]>::from(Sha256::digest(&descriptor))==*record_span.digest_data(),"removal-resume-control-changed")?;
                (raw,descriptor)
            }else{
                (metadata_bytes(book, release, installation_record::INVENTORY_NAME, installation_record::INVENTORY_LIMIT)?,
                    metadata_bytes(book, release, installation_record::RECORD_NAME, installation_record::RECORD_LIMIT)?)
            };
            let expected = installation_record::Expected { kind:installation_record::Kind::Ordinary,
                source_commit:binding.source_commit, runtime_manifest:binding.runtime_manifest_sha256,
                install_root:book.recorded_directory(destination)?, release_directory:generation.release_directory_data() };
            let record = installation_record::Record::parse_for_release_data(&descriptor, &raw, &expected, generation.release_data())?;
            check(record.instance() == generation.instance_data(), "maintenance-generation-instance")?;
            let inventory = Inventory::parse_for_release(&raw, binding.runtime_manifest_sha256, binding.release)?;
            let index = inventory.index()?;
            let mut before_present=(0,0);
            if let Some((source,plan))=resume.as_mut(){
                source.authenticated_selection(book)?;before_present=(plan.present_files,plan.present_bytes);
                plan.begin_generation(generation,&index)?;
                let present=match book.named(Some(release),"runtime"){Ok(_)=>true,Err(Errno::ENOENT)=>false,
                    Err(_)=>return Err("removal-resume-runtime-name")};
                let mut wanted:BTreeSet<String>=[installation_record::INVENTORY_NAME,installation_record::RECORD_NAME]
                    .into_iter().map(str::to_owned).collect();
                if present{wanted.insert("runtime".into());}
                exact_roster(book,release,&wanted)?;
                if present{let runtime=book.open(Some(release),"runtime",true)?;
                    audit_tree_mode(book,runtime,"runtime",&index,0,Some(&mut **plan))?;
                    book.forward_close(runtime,"maintenance-runtime-close")?;
                }else{plan.absent(book,release,"runtime","runtime",true,None,0)?;}
            }else{
                payload_generation_begin(book,generation)?;
                exact_roster(book, release, &["runtime", installation_record::INVENTORY_NAME, installation_record::RECORD_NAME]
                    .into_iter().map(str::to_owned).collect())?;
                let runtime = book.open(Some(release), "runtime", true)?;
                audit_tree(book, runtime, "runtime", &index, 0)?;
                book.forward_close(runtime, "maintenance-runtime-close")?;
            }
            let app_name = match generation.retained_invocation_data() {
                None => paths::APP_NAME.to_owned(), Some(invocation) => data(transaction::retained_app_name_data(invocation))?,
            };
            let (app_parent,app_leaf)=if let Some((source,_))=resume.as_ref(){
                if generation.retained_invocation_data().is_none(){(source.genesis_archive(book)?,"app")}
                else{(destination,app_name.as_str())}
            }else{(destination,app_name.as_str())};
            let app = match book.named(Some(app_parent), app_leaf) {
                Err(Errno::ENOENT) if resume.is_some()=>{
                    resume.as_mut().ok_or("removal-resume-mode")?.1.absent(book,app_parent,app_leaf,"app",true,None,0)?;None
                },
                Err(Errno::ENOENT) if allow_missing_app && generation.retained_invocation_data().is_none() => None,
                Err(_) => return Err("maintenance-app-missing-or-refused"),
                Ok(_) => {
                    let original = book.open(Some(app_parent), app_leaf, true)?;
                    check(app_identity(book, original)? == generation.app_identity_data(), "maintenance-app-original")?;
                    if let Some((_,plan))=resume.as_mut(){
                        if generation.retained_invocation_data().is_none(){plan.current_app=Some(book.identity(original)?);}
                        audit_tree_mode(book,original,"app",&index,0,Some(&mut **plan))?;
                    }else{audit_tree(book, original, "app", &index, 0)?;} Some(original)
                },
            };
            let mut cost = GenerationCostData { files:2, bytes:(raw.len() + descriptor.len()) as u64 };
            if let Some((_,plan))=resume.as_ref(){
                cost.files=cost.files.checked_add(plan.present_files.checked_sub(before_present.0).ok_or("removal-resume-plan-count")?)
                    .ok_or("removal-resume-plan-count")?;
                cost.bytes=cost.bytes.checked_add(plan.present_bytes.checked_sub(before_present.1).ok_or("removal-resume-plan-count")?)
                    .ok_or("removal-resume-plan-count")?;
            }else{for (path, entry) in &index.files {
                if app.is_some() || !path.starts_with("app/") {
                    cost.files += 1; cost.bytes = cost.bytes.checked_add(entry.size).ok_or("maintenance-payload-bound")?;
                }
            }}
            if !keep {
                if let Some(app) = app { book.forward_close(app, "maintenance-retained-app-close")?; }
                book.forward_close(release, "maintenance-retained-release-close")?;
            }
            if let Some((_,plan))=resume{plan.end_generation()?;}else{payload_generation_end(book)?;}
            Ok((app, release, cost, (raw.len() + descriptor.len()) as u64))
        }
        // Strict known-control prelude, still DATA. It may not select a payload
        // opener or enter M. Reuses read_history and the sole archive reader.
        // A SOURCE-named scalar size census precedes retained History parsing;
        // this is a memory quote, not another metadata/payload walker.
        fn removal_resume_history_quote(book:&mut Install,root:usize,selected:&ReleaseSetData)->Result<u64> {
            let (original,raw)=metadata_original(book,root,transaction::STATE_NAME,transaction::STATE_LIMIT)?;
            let state=data(StateData::parse_data(&raw,selected))?;
            check(state.mutation_recorded_data(),"removal-resume-current-state")?;
            let mut bytes=raw.len() as u64;let mut names=BTreeSet::new();
            let mut add=|name:String,limit:usize|->Result<()> {
                check(names.insert(name.clone()) && names.len()<=192,"removal-resume-history-count")?;
                book.clock()?;let actual=book.named(Some(root),&name).map_err(|_|"removal-resume-history-name")?;
                check(actual.st_mode&0o170000==0o100000 && actual.st_mode&0o7777==0o444
                    && actual.st_uid==0 && actual.st_gid==0 && actual.st_nlink==1 && actual.st_flags==0
                    && actual.st_size>0 && actual.st_size as u64<=limit as u64,"removal-resume-history-shape")?;
                bytes=bytes.checked_add(actual.st_size as u64).ok_or("removal-resume-history-bound")?;Ok(())
            };
            add(data(transaction::intent_name_data(state.invocation_data()))?,transaction::INTENT_LIMIT)?;
            add(data(transaction::capsule_name_data(state.invocation_data()))?,transaction::CAPSULE_LIMIT)?;
            for row in state.evidence_data() {
                add(data(transaction::intent_name_data(row.invocation))?,transaction::INTENT_LIMIT)?;
                add(data(transaction::archived_state_name_data(row.invocation))?,transaction::STATE_LIMIT)?;
                add(data(transaction::capsule_name_data(row.invocation))?,transaction::CAPSULE_LIMIT)?;
            }
            drop(add);
            // Includes the live raw+serde/typed representations, bounded name
            // indices, current scalar-read overlap and the caller's source cells.
            let quote=bytes.checked_mul(3).and_then(|n|n.checked_add(256*1024))
                .and_then(|n|n.checked_add(book.removal_control_reserved))
                .filter(|n|*n<=16*1024*1024).ok_or("removal-resume-history-bound")?;
            held_bytes(book,original,&raw)?;book.forward_close(original,"removal-resume-history-quote-close")?;Ok(quote)
        }
        fn removal_resume_known_root_names(book:&Install,history:&History,selected:&ReleaseSetData,root:usize)->Result<BTreeSet<String>> {
            check(history.current.state.current_data().release_data()==selected.current_data(),"removal-resume-current-release")?;
            let mut names:BTreeSet<String>=["versions",paths::MAINTENANCE_GATE_NAME,paths::REGISTRATION_GATE_NAME,
                transaction::STATE_NAME].into_iter().map(str::to_owned).collect();
            for generation in std::iter::once(history.current.state.current_data()).chain(history.current.state.retained_data()) {
                let pair=control_names(selected,generation.release_data().binding_data().release)?;
                names.insert(pair.0);names.insert(pair.1);
                if let Some(invocation)=generation.retained_invocation_data() {
                    let name=data(transaction::retained_app_name_data(invocation))?;
                    match book.named(Some(root),&name) {Ok(_)=>{names.insert(name);},Err(Errno::ENOENT)=>{},
                        Err(_)=>return Err("removal-resume-retained-app-name")}
                }
            }
            for record in history.originals.values().chain(std::iter::once(&history.current)) {
                let invocation=record.intent.invocation_data();
                names.insert(data(transaction::intent_name_data(invocation))?);
                names.insert(data(transaction::capsule_name_data(invocation))?);
                if invocation!=history.current.state.invocation_data(){names.insert(data(transaction::archived_state_name_data(invocation))?);}
                if record.intent.action_data()!=ActionData::SamePackageNoop {names.insert(format!(".install-{invocation}"));}
            }
            check(names.len()<=286,"removal-resume-root-count")?;Ok(names)
        }
        pub(super) fn removal_resume_prelude(book:&mut Install,source:&worker::RemovalResumeSource)
            ->Result<(RemovalArchiveCensus,[u8;32])> {
            let selected=source.prelude_selection_data(book)?;
            reserve_removal_snapshot_work(book)?;
            let root=source.root_original();let quote=removal_resume_history_quote(book,root,selected)?;
            let history=read_history(book,root,selected)?;
            check(history.bytes.checked_mul(3).and_then(|n|n.checked_add(256*1024))
                .and_then(|n|n.checked_add(book.removal_control_reserved)).is_some_and(|n|n<=quote),
                "removal-resume-history-quote-changed")?;
            let wanted=removal_resume_known_root_names(book,&history,selected,root)?;
            let state_sha=Sha256::digest(&history.state_bytes).into();
            let state_original=history.state_original;
            held_bytes(book,state_original,&history.state_bytes)?;
            // No retained History overlaps the bounded semantic archive parser.
            drop(history);book.forward_close(state_original,"removal-resume-prelude-close")?;
            source.prelude_selection_data(book)?;
            let census=read_removal_archive_census(book,root,&wanted)?;
            source.prelude_selection_data(book)?;
            Ok((census,state_sha))
        }
        fn removal_resume_children_data(wanted:&BTreeSet<String>,actual:&BTreeMap<String,u64>)->bool {
            actual.iter().all(|(name,inode)|*inode!=0 && wanted.contains(name))
        }
        #[derive(Clone,Copy)]
        struct RemovalResumeForecast {files:u64,directories:u64,controls:u64,prior:u64}
        fn removal_resume_original_quote_data(used:usize,files:u64,directories:u64,controls:u64,prior:u64,walks:u64)->Option<u64> {
            // Every walk: one original per present file, directory+independent
            // roster per directory, <=2C metadata/history readers, 10P census (includes pending-prefix rereads)
            // plus 8P physical final POST, <=256 fixed generation/stage anchors.
            // Missing nodes cost no original. Forecast charges all signed nodes.
            let one=files.checked_add(directories.checked_mul(2)?)?.checked_add(controls.checked_mul(2)?)?
                .checked_add(prior.checked_mul(18)?)?.checked_add(256)?;
            (used as u64).checked_add(one.checked_mul(walks)?).filter(|n|*n<=24576)
        }
        fn removal_resume_inventory_quote_data(size:u64)->Option<usize> {
            // Original raw JSON, strict Value/typed/index/path overlap and the
            // maximum two simultaneously allocated directory-key sets. This is
            // a restrictive preallocation quote, not new available memory.
            usize::try_from(size).ok()?.checked_mul(8)?.checked_add(2*installation_record::FILE_LIMIT*1280)?.checked_add(256*1024)
        }
        fn removal_resume_forecast(book:&Install,source:&worker::RemovalResumeSource,history:&History,base:u64)->Result<RemovalResumeForecast> {
            let mut out=RemovalResumeForecast {files:0,directories:0,
                controls:source.genesis_data(book)?.controls_data().len() as u64,prior:source.history_rows_data()? as u64};
            check(out.controls<=SNAPSHOT_CONTROLS as u64 && out.prior<=64,"removal-resume-forecast-bound")?;
            for generation in std::iter::once(history.current.state.current_data()).chain(history.current.state.retained_data()) {
                source.authenticated_selection(book)?;
                let binding=generation.release_data().binding_data();
                let path=format!("versions/{}/{}",binding.release,installation_record::INVENTORY_NAME);
                let span=source.genesis_control_data(book,&path)?;
                check(*span.digest_data()==worker::removal_hex_data::<32>(binding.inventory_sha256)?,"removal-resume-generation-inventory")?;
                let extra=removal_resume_inventory_quote_data(span.len_data()).ok_or("removal-resume-inventory-memory")?;
                check(base.checked_add(extra as u64).is_some_and(|n|n<=16*1024*1024),"removal-resume-inventory-memory")?;
                let raw=source.read_genesis_control(book,&path)?;
                let inventory=Inventory::parse_for_release(&raw,binding.runtime_manifest_sha256,binding.release)?;
                let index=inventory.index()?;
                out.files=out.files.checked_add(index.files.len() as u64).ok_or("removal-resume-count")?;
                out.directories=out.directories.checked_add(index.directories.len() as u64).ok_or("removal-resume-count")?;
                book.clock()?;
            }
            check(removal_resume_original_quote_data(book.originals.len(),out.files,out.directories,out.controls,out.prior,2).is_some(),
                "removal-resume-original-reservation")?;
            // Hold the SOURCE/bootstrap/genesis originals throughout; depth16
            // needs at most17 tree FDs plus one file/roster, release+versions,
            // State, and two overlapping shallow history readers.
            let live=book.originals.iter().filter(|n|n.fd.is_some()).count();
            check(live.checked_add(24).and_then(|n|n.checked_add(book.removal_live_reserved)).and_then(|n|n.checked_add(if book.worker_deadline.is_some(){worker::EXTRA_LIVE}else{0}))
                .is_some_and(|n|n<=96),"removal-resume-live-reservation")?;Ok(out)
        }
        pub(super) struct RemovalResumeFirst {pub(super) fingerprint:[u8;32],forecast:RemovalResumeForecast}
        pub(super) struct RemovalResumeObservation {
            pub(super) plan:RemovalRemainingPlan,forecast:RemovalResumeForecast,
            storage:u64,control:u64,
        }
        impl RemovalResumeObservation {
            pub(super) fn fingerprint_data(&self)->Result<[u8;32]>{self.plan.fingerprint()}
            pub(super) fn into_first(self)->Result<RemovalResumeFirst> {
                Ok(RemovalResumeFirst {fingerprint:self.plan.fingerprint()?,forecast:self.forecast})
            }
            pub(super) fn charge_retained(&self,book:&mut Install)->Result<()> {
                self.plan.memory(0)?;
                check(self.plan.complete && self.plan.transient==0,"removal-resume-plan-incomplete")?;
                book.removal_control_reserved=book.removal_control_reserved.checked_add(self.plan.owned_bytes(0)? as u64)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-resume-control-bound")?;Ok(())
            }
            pub(super) fn continuation_budget(&self,book:&Install)->Result<()> {
                self.plan.memory(0)?;
                check(book.removal_control_reserved<=16*1024*1024,"removal-resume-control-bound")?;
                let f=self.forecast;
                // Source-derived upper bound BEFORE a future irreversible
                // continuation: no reset/reuse of already issued Book records.
                let count=f.files.checked_mul(2).and_then(|n|n.checked_add(f.directories.checked_mul(3)?))
                    .and_then(|n|n.checked_add(f.controls.checked_mul(2)?)).and_then(|n|n.checked_add(f.prior.checked_mul(8)?))
                    .and_then(|n|n.checked_add(64)).and_then(|n|n.checked_add(book.originals.len() as u64));
                check(count.is_some_and(|n|n<=24576) && self.control<=16*1024*1024 && self.storage<=installation_record::PAYLOAD_LIMIT,
                    "removal-resume-continuation-budget")
            }
        }
        fn removal_resume_compare_capture(book:&Install,source:&worker::RemovalResumeSource)->Result<()> {
            let capture=book.removal_snapshot_capture.as_ref().ok_or("removal-resume-capture-missing")?;
            check(!capture.failed && !capture.complete && capture.root==source.root_original(),"removal-resume-capture-state")?;
            let expected=source.genesis_data(book)?;
            let wanted=expected.controls_data().iter().filter(|span|span.kind_data()==0).count();
            check(capture.controls.len()==wanted,"removal-resume-control-census")?;
            for actual in &capture.controls {
                let old=source.genesis_control_data(book,&actual.path)?;
                check(actual.kind==0 && actual.identity==old.identity_data() && actual.flags==old.flags_data()
                    && actual.size==old.len_data() && actual.digest==*old.digest_data(),"removal-resume-control-changed")?;
            }
            for (kind,n,raw) in [(3,book.registration.participant,paths::REGISTRATION_GATE_BYTES),
                (4,book.gate.participant,paths::MAINTENANCE_GATE_BYTES)] {
                let n=n.ok_or("removal-resume-gate-missing")?;
                let path=&book.originals[n].name;
                let mut old=expected.controls_data().iter().filter(|span|span.kind_data()==kind && span.path_data()==path.as_str());
                let span=old.next().ok_or("removal-resume-gate-span")?;
                check(old.next().is_none() && span.identity_data()==book.identity(n)? && span.flags_data()==0
                    && span.len_data()==raw.len() as u64 && *span.digest_data()==<[u8;32]>::from(Sha256::digest(raw)),
                    "removal-resume-gate-changed")?;held_bytes(book,n,raw)?;
            }capture.memory(0)?;Ok(())
        }
        pub(super) fn observe_removal_resume(book:&mut Install,source:&worker::RemovalResumeSource,
            prior:Option<&RemovalResumeFirst>)->Result<RemovalResumeObservation> {
            let selected=source.authenticated_selection(book)?;let root=source.root_original();
            check(book.removal_payload_plan.is_none() && book.removal_snapshot_capture.is_none(),"removal-resume-walk-once")?;
            // Reuse only the existing metadata capture hooks. This transient
            // census never finishes, emits a snapshot or gains writer authority.
            RemovalSnapshotCapture::begin(book,root)?;
            let base=removal_resume_history_quote(book,root,selected)?;
            let history=read_history(book,root,selected)?;
            check(history.bytes.checked_mul(3).and_then(|n|n.checked_add(256*1024))
                .and_then(|n|n.checked_add(book.removal_control_reserved)).is_some_and(|n|n<=base),"removal-resume-history-quote-changed")?;
            let genesis=source.genesis_data(book)?.binding_data()?;
            check(<[u8;32]>::from(Sha256::digest(&history.state_bytes))==genesis.digests_data()[3],"removal-resume-current-state-changed")?;
            let forecast=if let Some(prior)=prior {
                check(removal_resume_original_quote_data(book.originals.len(),prior.forecast.files,prior.forecast.directories,
                    prior.forecast.controls,prior.forecast.prior,1).is_some(),"removal-resume-original-reservation")?;prior.forecast
            }else{removal_resume_forecast(book,source,&history,base)?};
            let mut plan=RemovalRemainingPlan::new(book,source,base)?;
            let versions=book.open(Some(root),"versions",true)?;book.recorded_directory(versions)?;
            let mut versions_wanted=BTreeSet::new();let mut controls_wanted=BTreeSet::new();
            let mut payload=0u64;let mut evidence=history.bytes;
            for generation in std::iter::once(history.current.state.current_data()).chain(history.current.state.retained_data()) {
                let binding=generation.release_data().binding_data();
                let path=format!("versions/{}/{}",binding.release,installation_record::INVENTORY_NAME);
                plan.transient=removal_resume_inventory_quote_data(source.genesis_control_data(book,&path)?.len_data())
                    .ok_or("removal-resume-inventory-memory")?;plan.memory(0)?;
                let (_,_,cost,_)=audit_generation_mode(book,root,versions,&generation,false,false,Some((source,&mut plan)))?;
                plan.transient=0;plan.memory(0)?;
                payload=payload.checked_add(cost.bytes).ok_or("removal-resume-storage")?;
                let (_,bytes)=generation_controls(book,root,&generation,selected,&mut controls_wanted,false)?;
                payload=payload.checked_add(bytes).ok_or("removal-resume-storage")?;
                check(versions_wanted.insert(binding.release.to_owned()),"removal-resume-generation-duplicate")?;
            }
            for record in history.originals.values().chain(std::iter::once(&history.current)) {stage_roster(book,root,record,&mut evidence)?;}
            let wanted=removal_resume_known_root_names(book,&history,selected,root)?;
            exact_roster(book,versions,&versions_wanted)?;book.forward_close(versions,"removal-resume-versions-close")?;
            // The one sole linked parser/classifier, with all six actual slots;
            // captures raw facts only, never SOURCE or R/M authority.
            let census=read_removal_archive_census(book,root,&wanted)?;
            source.history_matches(book,&census)?;
            let mut full=wanted;
            for row in census.rows(){check(full.insert(row.name().to_owned()),"removal-resume-root-collision")?;}
            exact_roster(book,root,&full)?;
            removal_resume_compare_capture(book,source)?;
            check(plan.expected_files==forecast.files && plan.expected_directories==forecast.directories,"removal-resume-forecast-changed")?;
            let storage=payload.checked_add(evidence).and_then(|n|n.checked_add(source.history_storage_data().ok()?))
                .and_then(|n|n.checked_add((paths::MAINTENANCE_GATE_BYTES.len()+paths::REGISTRATION_GATE_BYTES.len()) as u64))
                .filter(|n|*n<=installation_record::PAYLOAD_LIMIT).ok_or("removal-resume-storage")?;
            held_bytes(book,history.state_original,&history.state_bytes)?;
            book.forward_close(history.state_original,"removal-resume-state-close")?;
            drop(history);drop(census);
            // Drop the transient capture/History before retaining the plan for
            // the second observation. No original ID or work quote is reset.
            let capture=book.removal_snapshot_capture.take().ok_or("removal-resume-capture-missing")?;
            check(!capture.failed && !capture.complete,"removal-resume-capture-state")?;drop(capture);
            plan.complete=true;plan.memory(0)?;
            source.final_original_post(book)?;
            Ok(RemovalResumeObservation {plan,forecast,storage,control:base})
        }
        #[cfg(test)]
        pub(super) fn removal_resume_observation_data_checks() {
            let wanted:BTreeSet<String>=["a","b"].into_iter().map(str::to_owned).collect();
            assert!(removal_resume_children_data(&wanted,&BTreeMap::new()));
            assert!(removal_resume_children_data(&wanted,&BTreeMap::from([("a".into(),1)])));
            assert!(!removal_resume_children_data(&wanted,&BTreeMap::from([("foreign".into(),1)])));
            assert!(!removal_resume_children_data(&wanted,&BTreeMap::from([("a".into(),0)])));
            let one=3+2*4+2*5+18*6+256;
            assert_eq!(removal_resume_original_quote_data(11,3,4,5,6,2),Some(11+2*one));
            assert_eq!(removal_resume_original_quote_data((24576-2*one) as usize,3,4,5,6,2),Some(24576));
            assert!(removal_resume_original_quote_data((24577-2*one) as usize,3,4,5,6,2).is_none());
            for values in [(u64::MAX,0,0,0),(0,u64::MAX,0,0),(0,0,u64::MAX,0),(0,0,0,u64::MAX)] {
                assert!(removal_resume_original_quote_data(0,values.0,values.1,values.2,values.3,2).is_none());
            }
            assert!(removal_resume_inventory_quote_data(u64::MAX).is_none());
            use mobile_release_desktop::macos_remove_record::{PayloadPresenceData as P,AppSlotsData as A};
            let id=Identity {dev:1,ino:2,mode:0o40555,uid:0,gid:0,links:2,size:0,mtime:0,mtime_ns:0,ctime:0,ctime_ns:0};
            let mut plan=RemovalRemainingPlan {nodes:Vec::new(),generations:Vec::new(),stack:[None;17],active:None,
                base:0,transient:0,expected_files:1,present_files:0,present_bytes:0,expected_directories:2,current_app:None,complete:false};
            assert_eq!(plan.payload_presence_data(),P::Unknown);assert_eq!(plan.app_slots_data(),A::Unknown);
            plan.nodes.push(RemovalRemainingNode {generation:0,path:"app".into(),parent:None,directory:true,size:0,digest:[0;32],
                executable:false,presence:RemovalRemainingPresence::Absent {parent:id}});
            plan.complete=true;assert!(plan.payload_all_absent_data());assert_eq!(plan.payload_presence_data(),P::AllAbsent);
            assert_eq!(plan.app_slots_data(),A::Neither);
            // An actual remaining EMPTY app directory is not total absence.
            // No missing-directory witness is represented as an all-zero inode.
            plan.current_app=Some(id);plan.nodes[0].presence=RemovalRemainingPresence::Present {identity:id,flags:0};
            assert!(!plan.payload_all_absent_data());assert_eq!(plan.payload_presence_data(),P::PartialInRosterMatching);
            assert_eq!(plan.app_slots_data(),A::NewOnly);
            plan.present_files=1;assert_eq!(plan.payload_presence_data(),P::AllPresentMatching);
            let first=plan.fingerprint().unwrap();
            plan.nodes[0].presence=RemovalRemainingPresence::Present {identity:Identity{ino:3,..id},flags:0};
            assert_ne!(first,plan.fingerprint().unwrap());
        }
        fn stage_roster(book: &mut Install, root: usize, record: &Recorded, evidence_bytes: &mut u64) -> Result<()> {
            if record.intent.action_data() == ActionData::SamePackageNoop { return Ok(()); }
            let name = format!(".install-{}", record.intent.invocation_data());
            let stage = book.open(Some(root), &name, true)?; book.protected(stage, true, Some(0o700))?;
            native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_| "maintenance-stage-attributes")?;
            check(stat::fstat(book.fd(stage)?).map_err(|_| "maintenance-stage-stat")?.st_flags == 0,
                "maintenance-stage-flags")?;
            let phases: &[&str] = if record.intent.action_data() == ActionData::RestoreFixedApp {
                &["staging-created", "prepared", "app-publication-confirmed"]
            } else { &["staging-created", "prepared", "runtime-publication-confirmed", "both-publications-confirmed"] };
            exact_roster(book, stage, &phases.iter().map(|phase| format!("{phase}.json")).collect())?;
            for phase in phases {
                let body = metadata_bytes(book, stage, &format!("{phase}.json"), transaction::STATE_LIMIT)?;
                *evidence_bytes = evidence_bytes.checked_add(body.len() as u64).ok_or("maintenance-control-bound")?;
                let value = mobile_release_desktop::protocol::strict_json(&body).map_err(|_| "maintenance-stage-record")?;
                check(value.is_object() && value["schemaVersion"] == 1 && value["phase"] == *phase
                    && value["release"] == record.intent.next_data().binding_data().release
                    && value["inventorySha256"] == record.intent.next_data().binding_data().inventory_sha256
                    && value["originalSettlement"] == "pending-final-closes", "maintenance-stage-record")?;
            }
            book.check_name(stage, true)?; book.forward_close(stage, "maintenance-stage-close")
        }
        pub(super) fn observe(book: &mut Install, prepared: PreparedFresh, selected: ReleaseSetData,
            pending_intent: Option<&str>) -> Result<Observed> {
            selected_compile(&selected)?;
            check(book.gate.verified && (book.gate.exclusive_acquired || book.worker_stderr_is_gate),
                "maintenance-original-gate-required")?;
            observe_admitted(book,prepared,selected,pending_intent)
        }
        // Only this module can access the inner writer-shaped observation.
        // No conversion exposes it to the removal Parent or to the renderer.
        pub(super) struct RemovalObserved {
            inner: Observed, inventory_original: usize, record_original: usize, record_bytes: Vec<u8>,
        }
        // Comparison DATA only. It cannot create a RemovalObserved or grant
        // writer authority; the caller still owns the actual complete audit.
        pub(super) fn removal_current_only_data(action: ActionData, present: [bool;2],
            intent: bool, controls: bool, current: bool) -> bool {
            action==ActionData::SamePackageNoop && present==[true;2] && !intent && controls && current
        }
        impl RemovalObserved {
            pub(super) fn inventory(&self) -> &Inventory { &self.inner.prepared.inventory }
            pub(super) fn inventory_bytes(&self) -> &[u8] { &self.inner.prepared.inventory_bytes }
            pub(super) fn post(&self, book: &Install) -> Result<()> {
                held_inventory(book,self.inventory_original,self.inventory_bytes())?;
                held_bytes(book,self.record_original,&self.record_bytes)?;
                self.inner.controls_post(book)?;
                let history=self.inner.history.as_ref().ok_or("removal-current-history")?;
                held_bytes(book,history.state_original,&history.state_bytes)?;
                book.check_name(self.inner.old_app.ok_or("removal-current-app")?,true)?;
                book.check_name(self.inner.old_release.ok_or("removal-current-release")?,true)
            }
        }
        pub(super) fn observe_removal(book: &mut Install, source: &worker::RemovalAdmission) -> Result<RemovalObserved> {
            let result=observe_removal_with_archives(book,source);
            if result.is_err(){if let Some(scan)=book.removal_archive_scan.as_mut(){scan.phase=RemovalArchivePhase::Refused;}}
            result
        }
        fn observe_removal_with_archives(book:&mut Install,source:&worker::RemovalAdmission)->Result<RemovalObserved> {
            let selected=source.current_selection(book)?.clone();
            source.reservation_post(book)?;
            source.existing_maintenance_post(book)?;
            let root=source.root_original();
            begin_removal_archive_census(book,root,false)?;
            let versions=book.open(Some(root),"versions",true)?;
            book.protected(versions,true,Some(0o755))?;
            let binding=selected.current_data().binding_data();
            let release=book.open(Some(versions),binding.release,true)?;
            book.protected(release,true,Some(0o755))?;
            let (inventory_original,raw)=metadata_original(book,release,installation_record::INVENTORY_NAME,
                installation_record::INVENTORY_LIMIT)?;
            check(hash(&raw)==binding.inventory_sha256,"removal-current-inventory")?;
            let (record_original,record_bytes)=metadata_original(book,release,installation_record::RECORD_NAME,
                installation_record::RECORD_LIMIT)?;
            let expected=installation_record::Expected { kind:installation_record::Kind::Ordinary,
                source_commit:binding.source_commit,runtime_manifest:binding.runtime_manifest_sha256,
                install_root:book.recorded_directory(root)?,release_directory:book.recorded_directory(release)? };
            let record=installation_record::Record::parse_for_release_data(&record_bytes,&raw,&expected,selected.current_data())?;
            let inventory=Inventory::parse_for_release(&raw,binding.runtime_manifest_sha256,binding.release)?;
            let prepared=PreparedFresh { input:root,inventory,inventory_bytes:raw,destination:root,versions };
            let observed=observe_admitted(book,prepared,selected,None)?;
            check(removal_current_only_data(observed.action,[observed.old_app.is_some(),observed.old_release.is_some()],
                observed.intent.is_some(),observed.controls.is_some(),observed.history.as_ref().is_some_and(|history|
                    history.current.state.current_data().release_data()==observed.selected.current_data())),
                "removal-current-only")?;
            observed.incoming_controls(book,source.installed_bytes(),source.installed_signature_bytes())?;
            check(observed.history.as_ref().is_some_and(|history|
                history.current.state.current_data().instance_data()==record.instance()),"removal-current-record")?;
            source.reservation_post(book)?;
            let value=RemovalObserved { inner:observed,inventory_original,record_original,record_bytes };
            value.post(book)?;complete_removal_archive_census(book)?;Ok(value)
        }
        // Consumes the old observation, not a second overlapping 16MiB
        // allowance. Reuse its inventory/record/versions originals; only the
        // small current-state raw anchor overlaps the complete fresh walker.
        pub(super) fn reobserve_removal_exclusive(book:&mut Install,source:&worker::RemovalAdmission,
            exclusion:&worker::RemovalExclusion,old:RemovalObserved)->Result<RemovalObserved> {
            let result=reobserve_removal_with_archives(book,source,exclusion,old);
            if result.is_err(){if let Some(scan)=book.removal_archive_scan.as_mut(){scan.phase=RemovalArchivePhase::Refused;}}
            result
        }
        fn reobserve_removal_with_archives(book:&mut Install,source:&worker::RemovalAdmission,
            exclusion:&worker::RemovalExclusion,old:RemovalObserved)->Result<RemovalObserved> {
            exclusion.post(book,source)?; old.post(book)?;
            begin_removal_archive_census(book,source.root_original(),true)?;
            let RemovalObserved { inner,inventory_original,record_original,record_bytes }=old;
            let Observed { prepared,selected,action,history,old_app,old_release,intent,intent_original,controls }=inner;
            check(action==ActionData::SamePackageNoop && intent.is_none() && intent_original.is_none(),"removal-current-only")?;
            let history=history.ok_or("removal-current-history")?;
            let controls=controls.ok_or("removal-current-controls")?;
            let redundant=[controls.originals[0],controls.originals[1],old_app.ok_or("removal-current-app")?,
                old_release.ok_or("removal-current-release")?];
            let anchors=[prepared.input,prepared.destination,prepared.versions,inventory_original,record_original,
                history.state_original,book.originals[inventory_original].parent.ok_or("removal-inventory-parent")?,
                book.originals[record_original].parent.ok_or("removal-record-parent")?,
                book.registration.participant.ok_or("removal-original-reservation")?];
            for (position,index) in redundant.iter().copied().enumerate() {
                check(!anchors.contains(&index) && !source.retained_source_index(index)
                    && !redundant[..position].contains(&index),"removal-observation-alias")?;
                let original=book.originals.get(index).ok_or("removal-observation-original")?;
                check(original.role==Role::Reader && original.state==State::Owned,"removal-observation-original")?;
            }
            // All remaining originals stay in the same Book if any known
            // close or clock POST fails; no rollback/adoption by index.
            for index in redundant { book.forward_close(index,"removal-observation-close")?; }
            drop(controls);
            let History { current,originals,state_original,state_bytes,bytes:_ }=history;
            drop(current); drop(originals);
            // Discard parsed history before calling the complete walker.
            book.removal_control_reserved=worker::removal_reobserve_budget_data(book.removal_control_reserved,state_bytes.capacity())?;
            exclusion.post(book,source)?;
            let mut observed=observe_admitted(book,prepared,selected,None)?;
            check(removal_current_only_data(observed.action,[observed.old_app.is_some(),observed.old_release.is_some()],
                observed.intent.is_some(),observed.controls.is_some(),observed.history.as_ref().is_some_and(|history|
                    history.current.state.current_data().release_data()==observed.selected.current_data())),"removal-current-only")?;
            observed.incoming_controls(book,source.installed_bytes(),source.installed_signature_bytes())?;
            let current=observed.history.as_mut().ok_or("removal-current-history")?;
            held_bytes(book,state_original,&state_bytes)?;
            check(current.state_original!=state_original && current.state_bytes==state_bytes
                && book.identity(current.state_original)?==book.identity(state_original)?,"removal-state-changed")?;
            book.forward_close(current.state_original,"removal-state-duplicate-close")?;
            current.state_original=state_original;
            current.state_bytes=state_bytes;
            // Same original raw installation record must still correspond to
            // the freshly audited current state, not merely the same release.
            let binding=observed.selected.current_data().binding_data();
            let release=book.originals[record_original].parent.ok_or("removal-record-parent")?;
            let expected=installation_record::Expected { kind:installation_record::Kind::Ordinary,
                source_commit:binding.source_commit,runtime_manifest:binding.runtime_manifest_sha256,
                install_root:book.recorded_directory(observed.prepared.destination)?,release_directory:book.recorded_directory(release)? };
            let record=installation_record::Record::parse_for_release_data(&record_bytes,&observed.prepared.inventory_bytes,
                &expected,observed.selected.current_data())?;
            check(observed.history.as_ref().is_some_and(|h|h.current.state.current_data().instance_data()==record.instance()),
                "removal-current-record")?;
            let value=RemovalObserved { inner:observed,inventory_original,record_original,record_bytes };
            value.post(book)?;exclusion.post(book,source)?;complete_removal_archive_census(book)?;Ok(value)
        }
        fn observe_admitted(book: &mut Install, prepared: PreparedFresh, selected: ReleaseSetData,
            pending_intent: Option<&str>) -> Result<Observed> {
            let root = prepared.destination; let versions = prepared.versions;
            let history = match book.named(Some(root), transaction::STATE_NAME) {
                Err(Errno::ENOENT) => None,
                Err(_) => return Err("maintenance-state-observation"),
                Ok(_) => Some(read_history(book, root, &selected)?),
            };
            let mut root_names: BTreeSet<String> = ["versions", paths::MAINTENANCE_GATE_NAME].into_iter().map(str::to_owned).collect();
            // Before parent creation only an authenticated existing R is in the
            // exact roster. The worker requires the parent's provisioned leaf;
            // it authenticates that original after actual GO, before effects.
            if book.registration.verified || book.worker_stderr_is_gate { root_names.insert(paths::REGISTRATION_GATE_NAME.into()); }
            let mut version_names = BTreeSet::new(); let mut costs = Vec::new(); let mut evidence_bytes = 0u64;
            let mut metadata_control = 0u64; let mut controls = None;
            let (action, old_app, old_release, invocation_count) = if let Some(history) = &history {
                root_names.insert(transaction::STATE_NAME.into()); evidence_bytes = history.bytes;
                let generation = history.current.state.current_data();
                let same = generation.release_data() == selected.current_data();
                let (app, release, cost, metadata) = audit_generation(book, root, versions, &generation, same, true)?;
                costs.push(cost); metadata_control = metadata_control.checked_add(metadata).ok_or("maintenance-control-bound")?;
                let (pair, count) = generation_controls(book,root,&generation,&selected,&mut root_names,same)?;
                controls = pair; metadata_control = metadata_control.checked_add(count).ok_or("maintenance-control-bound")?;
                version_names.insert(generation.release_data().binding_data().release.to_owned());
                if app.is_some() { root_names.insert(paths::APP_NAME.into()); }
                for generation in history.current.state.retained_data() {
                    let (_, _, cost, metadata) = audit_generation(book, root, versions, &generation, false, false)?;
                    costs.push(cost); metadata_control = metadata_control.checked_add(metadata).ok_or("maintenance-control-bound")?;
                    let (_, count) = generation_controls(book,root,&generation,&selected,&mut root_names,false)?;
                    metadata_control = metadata_control.checked_add(count).ok_or("maintenance-control-bound")?;
                    version_names.insert(generation.release_data().binding_data().release.to_owned());
                    root_names.insert(data(transaction::retained_app_name_data(generation.retained_invocation_data()
                        .ok_or("maintenance-retained-shape")?))?);
                }
                for record in history.originals.values().chain(std::iter::once(&history.current)) {
                    let invocation = record.intent.invocation_data();
                    root_names.insert(data(transaction::intent_name_data(invocation))?);
                    root_names.insert(data(transaction::capsule_name_data(invocation))?);
                    if invocation != history.current.state.invocation_data() {
                        root_names.insert(data(transaction::archived_state_name_data(invocation))?);
                    }
                    if record.intent.action_data() != ActionData::SamePackageNoop { root_names.insert(format!(".install-{invocation}")); }
                    stage_roster(book, root, record, &mut evidence_bytes)?;
                }
                let action = if same { if app.is_some() { ActionData::SamePackageNoop } else { ActionData::RestoreFixedApp } }
                    else {
                        check(app.is_some() && selected.predecessor_data().contains(generation.release_data()), "maintenance-predecessor")?;
                        book.absent(versions, paths::RELEASE)?; ActionData::Update
                    };
                (action, app, Some(release), history.originals.len() + 2)
            } else {
                book.absent(root, paths::APP_NAME)?; book.absent(versions, paths::RELEASE)?;
                (ActionData::FreshInstall, None, None, 1)
            };
            if matches!(action,ActionData::FreshInstall | ActionData::Update) {
                let names = control_names(&selected,selected.current_data().binding_data().release)?;
                book.absent(root,&names.0)?; book.absent(root,&names.1)?;
            }
            if let Some(invocation) = pending_intent {
                check(worker::invocation_valid(invocation) && history.as_ref().is_none_or(|h|
                    invocation != h.current.state.invocation_data() && !h.originals.contains_key(invocation)), "maintenance-invocation-reused")?;
                root_names.insert(data(transaction::intent_name_data(invocation))?);
            }
            removal_archive_root_names(book,root,&mut root_names)?;
            exact_roster(book, root, &root_names)?; exact_roster(book, versions, &version_names)?;
            let incoming = prepared.inventory.index()?;
            let copy_app_only = action == ActionData::RestoreFixedApp;
            let mut incoming_cost = GenerationCostData { files:0, bytes:0 };
            if action != ActionData::SamePackageNoop {
                for (path, entry) in &incoming.files {
                    if !copy_app_only || path.starts_with("app/") {
                        incoming_cost.files += 1;
                        incoming_cost.bytes = incoming_cost.bytes.checked_add(entry.size).ok_or("maintenance-payload-bound")?;
                    }
                }
            }
            let copy_files = incoming_cost.files;
            if copy_app_only {
                let current = costs.first_mut().ok_or("maintenance-generation-missing")?;
                current.files = current.files.checked_add(incoming_cost.files).ok_or("maintenance-payload-bound")?;
                current.bytes = current.bytes.checked_add(incoming_cost.bytes).ok_or("maintenance-payload-bound")?;
            } else if incoming_cost.files > 0 {
                incoming_cost.files += 2;
                incoming_cost.bytes = incoming_cost.bytes.checked_add(prepared.inventory_bytes.len() as u64)
                    .and_then(|n| n.checked_add(installation_record::RECORD_LIMIT as u64)).ok_or("maintenance-payload-bound")?;
                costs.push(incoming_cost);
            }
            // Gates are root-wide permanent storage, not release metadata or
            // another generation. Charge both once inside unchanged aggregate caps.
            let root_cost = costs.first_mut().ok_or("maintenance-generation-missing")?;
            root_cost.files = root_cost.files.checked_add(2).ok_or("maintenance-payload-bound")?;
            root_cost.bytes = root_cost.bytes.checked_add((paths::MAINTENANCE_GATE_BYTES.len()
                + paths::REGISTRATION_GATE_BYTES.len()) as u64).ok_or("maintenance-payload-bound")?;
            let selected_bytes = selected.encode_data().map_err(|_| "maintenance-selected-shape")?;
            check(EXPORT_LIMIT == transaction::REQUEST_EXPORT_LIMIT, "maintenance-request-bound")?;
            // Historical results are not success authority and need not be
            // opened here. Reserve their maximum persisted extent, including
            // the current result, inside the same aggregate storage cap.
            let result_bytes = (invocation_count as u64).checked_mul(EXPORT_LIMIT as u64).ok_or("maintenance-control-bound")?;
            let planned_evidence = evidence_bytes.checked_add((transaction::INTENT_LIMIT + transaction::STATE_LIMIT + transaction::CAPSULE_LIMIT) as u64)
                .and_then(|bytes| bytes.checked_add(result_bytes)).ok_or("maintenance-control-bound")?;
            let control_bound = evidence_bytes.checked_mul(3).and_then(|n| n.checked_add(metadata_control * 3))
                .and_then(|n| n.checked_add(prepared.inventory_bytes.len() as u64 * 3))
                .and_then(|n| n.checked_add(selected_bytes.len() as u64 + 128 * 1024 + 2 * EXPORT_LIMIT as u64))
                .and_then(|n| n.checked_add(6 * transaction::PRODUCER_CONTROL_LIMIT as u64))
                .and_then(|n| n.checked_add(book.removal_control_reserved))
                .ok_or("maintenance-control-bound")?;
            let records = (book.originals.len() as u64).checked_add(copy_files.checked_mul(3).ok_or("maintenance-original-bound")?)
                .and_then(|n| n.checked_add(incoming.directories.len() as u64 * 3 + 256 + 3)).ok_or("maintenance-original-bound")?;
            let live = book.originals.iter().filter(|r| r.fd.is_some()).count() as u64 + 2 * 16 + 12 + 1
                + book.removal_live_reserved as u64;
            let budget=data(transaction::BudgetData::checked_data(&costs, invocation_count, planned_evidence, control_bound, records, live))?;
            if book.removal_control_reserved!=0 {
                book.removal_observation_control=Some(control_bound);
                book.removal_observation_reserved=book.removal_control_reserved;
            }
            let prior_archive_bytes=removal_archive_storage_bytes(book)?;
            let complete_storage=budget.payload_totals_data().1.checked_add(planned_evidence)
                .and_then(|n|n.checked_add(costs.len() as u64*transaction::PRODUCER_CONTROL_LIMIT as u64))
                .and_then(|n|n.checked_add(prior_archive_bytes))
                .filter(|n|*n<=installation_record::PAYLOAD_LIMIT).ok_or("removal-snapshot-storage")?;
            if let Some(capture)=book.removal_snapshot_capture.as_mut() {
                check(!capture.complete && !capture.failed && capture.quote.is_none(),"removal-snapshot-quote-once")?;
                capture.quote=Some((control_bound,complete_storage));
            }
            Ok(Observed { prepared, selected, action, history, old_app, old_release, intent:None, intent_original:None,controls })
        }
        impl Observed {
            pub(super) fn controls_post(&self, book: &Install) -> Result<()> {
                if let Some(controls) = &self.controls { controls.post(book) } else {
                    check(matches!(self.action,ActionData::FreshInstall | ActionData::Update),"maintenance-producer-pair-missing")?;
                    let names = control_names(&self.selected,self.selected.current_data().binding_data().release)?;
                    book.absent(self.prepared.destination,&names.0)?; book.absent(self.prepared.destination,&names.1)
                }
            }
            pub(super) fn incoming_controls(&self, book: &Install, descriptor: &[u8], signature: &[u8]) -> Result<()> {
                use mobile_release_desktop::macos_install_producer as producer;
                check(!descriptor.is_empty() && descriptor.len() <= producer::DESCRIPTOR_LIMIT
                    && !signature.is_empty() && signature.len() <= producer::SIGNATURE_LIMIT,"maintenance-producer-bound")?;
                if let Some(pair) = &self.controls { check(pair.matches(descriptor,signature),"maintenance-producer-source-bytes")?; }
                self.controls_post(book)
            }
            pub(super) fn publish_controls(&mut self, book: &mut Install, state: &StateData,
                descriptor: &[u8], signature: &[u8]) -> Result<()> {
                // Called only after the parent's actual original join. The
                // child owns payload/state; the parent owns these public copies.
                // A partial pair never gets a capsule/export, deletion or retry.
                check(state.mutation_recorded_data() && state.current_data().release_data() == self.selected.current_data(),
                    "maintenance-producer-state")?;
                self.incoming_controls(book,descriptor,signature)?;
                if self.controls.is_none() {
                    let names = control_names(&self.selected,self.selected.current_data().binding_data().release)?;
                    let first = book.record_file(self.prepared.destination,&names.0,descriptor,Role::ReceiptWriter)?;
                    book.persist(self.prepared.destination,false)?; held_bytes(book,first,descriptor)?;
                    let second = book.record_file(self.prepared.destination,&names.1,signature,Role::ReceiptWriter)?;
                    book.persist(self.prepared.destination,false)?; held_bytes(book,second,signature)?;
                    self.controls = Some(ProducerControls { originals:[first,second],bytes:[descriptor.to_vec(),signature.to_vec()] });
                }
                self.incoming_controls(book,descriptor,signature)
            }
            pub(super) fn previous(&self) -> Option<(&StateData, &CapsuleData)> {
                self.history.as_ref().map(|h| (&h.current.state, &h.current.capsule))
            }
            fn intent_bytes(&self, invocation: &str, request_id: &str) -> Result<Vec<u8>> {
                data(IntentData::encode_data(invocation, request_id, self.action, self.previous(), &self.selected))
            }
            pub(super) fn create_intent(&mut self, book: &mut Install, invocation: &str, request_id: &str) -> Result<()> {
                check(self.intent.is_none() && self.intent_original.is_none(), "maintenance-intent-once")?;
                for name in [data(transaction::intent_name_data(invocation))?, data(transaction::capsule_name_data(invocation))?,
                    data(transaction::archived_state_name_data(invocation))?, data(transaction::retained_app_name_data(invocation))?,
                    format!(".install-{invocation}")] { book.absent(self.prepared.destination, &name)?; }
                if let Some(history) = &self.history {
                    book.absent(self.prepared.destination, &data(transaction::archived_state_name_data(history.current.state.invocation_data()))?)?;
                    held_bytes(book, history.state_original, &history.state_bytes)?;
                }
                // Reusing an earlier request would point at its already
                // reserved result, not this independent original invocation.
                if let Some(history) = &self.history {
                    check(history.originals.values().chain(std::iter::once(&history.current))
                        .all(|old| old.intent.request_id_data() != request_id), "maintenance-request-reused")?;
                }
                let bytes = self.intent_bytes(invocation, request_id)?;
                let original = book.record_file(self.prepared.destination, &data(transaction::intent_name_data(invocation))?,
                    &bytes, Role::ReceiptWriter)?;
                self.intent_original = Some(original); // Custody before persistence veto.
                book.persist(self.prepared.destination, false)?; held_bytes(book, original, &bytes)?;
                self.intent = Some(data(IntentData::parse_data(&bytes, &self.selected))?); Ok(())
            }
            pub(super) fn read_intent(&mut self, book: &mut Install, invocation: &str, request_id: &str) -> Result<()> {
                check(self.intent.is_none() && self.intent_original.is_none(), "maintenance-intent-once")?;
                let (original, bytes) = metadata_original(book, self.prepared.destination,
                    &data(transaction::intent_name_data(invocation))?, transaction::INTENT_LIMIT)?;
                self.intent_original = Some(original);
                check(bytes == self.intent_bytes(invocation, request_id)?, "maintenance-intent-binding")?;
                self.intent = Some(data(IntentData::parse_data(&bytes, &self.selected))?); Ok(())
            }
            pub(super) fn binding(&self, book: &Install) -> Result<serde_json::Value> {
                let intent = self.intent.as_ref().ok_or("maintenance-intent-missing")?;
                let original = self.intent_original.ok_or("maintenance-intent-missing")?;
                let previous = self.history.as_ref().map(|h| serde_json::json!({"stateSha256":h.current.state.digest_data(),
                    "capsuleSha256":h.current.capsule.digest_data()}));
                let release_bytes = self.selected.encode_data().map_err(|_| "maintenance-selected-shape")?;
                let releases = mobile_release_desktop::protocol::strict_json(&release_bytes).map_err(|_| "maintenance-selected-shape")?;
                Ok(serde_json::json!({"action":self.action,"requestId":intent.request_id_data(),"releases":releases,"intentSha256":intent.digest_data(),
                    "intentOriginal":worker::identity_data(book.identity(original)?),"previous":previous,
                    "producerControls":self.controls.as_ref().map(|pair| pair.binding(book)).transpose()?,
                    "installRoot":book.recorded_directory(self.prepared.destination)?,
                    "versionsRoot":book.recorded_directory(self.prepared.versions)?,
                    "oldApp":self.old_app.map(|n| app_identity(book,n).map(|i| i.fields_data())).transpose()?}))
            }
            pub(super) fn selected_from_binding(value: &serde_json::Value) -> Result<ReleaseSetData> {
                let fields = ["action","requestId","releases","intentSha256","intentOriginal","previous","producerControls","installRoot","versionsRoot","oldApp"];
                let map = value.as_object().ok_or("maintenance-init-shape")?;
                check(map.len() == fields.len() && fields.iter().all(|key| map.contains_key(*key)), "maintenance-init-shape")?;
                data(transaction::export_name_data(value["requestId"].as_str().ok_or("maintenance-request-shape")?))?;
                let bytes = serde_json::to_vec(&value["releases"]).map_err(|_| "maintenance-selected-shape")?;
                let target = if cfg!(target_arch="aarch64") { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64 }
                    else { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Intel };
                let selected = ReleaseSetData::parse_for_target_data(&bytes,target).map_err(|_| "maintenance-selected-shape")?;
                selected_compile(&selected)?; Ok(selected)
            }
        }
        fn timestamp(book: &Install) -> (u64, bool) {
            book.worker_deadline.as_ref().map_or((0,true), worker::Deadline::returned_time)
        }
        fn step(book: &mut Install, which: StepData, returned: ReturnedData, result: Result<()>, inverse: bool) -> Result<()> {
            let (at, uncertain) = timestamp(book);
            if uncertain { book.unknown = true; }
            let returned = if uncertain { ReturnedData::Unknown } else { returned };
            let effects = book.maintenance.as_mut().ok_or("maintenance-progress-missing")?;
            let recorded = if inverse { effects.progress.inverse_return_data(which,returned,at) }
                else { effects.progress.forward_return_data(which,returned,at) };
            if let Err(error) = result {
                // The preceding returned effect remains recorded even when a
                // following same-original POST/fsync/checkpoint refused.
                let _ = effects.progress.stop_data(if book.unknown { ReturnedData::Unknown } else { ReturnedData::KnownRefusal },at);
                return Err(error);
            }
            data(recorded)
        }
        fn returned_publication(book: &Install, state: &str) -> ReturnedData {
            if state == "confirmed" { ReturnedData::KnownSuccess }
            else if book.unknown || state == "unknown" { ReturnedData::Unknown } else { ReturnedData::KnownRefusal }
        }
        // Only known authorized rename metadata may differ. Immutable identity,
        // content extent, mode/owner/link count and mtime remain invariant; ctime
        // is recaptured after the exact known name transition, never ignored on
        // an unmutated original. Both held and named POST must agree in full.
        fn same_renamed(before: Identity, after: Identity) -> bool {
            before.dev == after.dev && before.ino == after.ino && before.mode == after.mode
                && before.uid == after.uid && before.gid == after.gid && before.links == after.links
                && before.size == after.size && before.mtime == after.mtime && before.mtime_ns == after.mtime_ns
        }
        fn rebind_renamed(book: &mut Install, original: usize, parent: usize, name: &str) -> Result<()> {
            let before = book.identity(original)?;
            let actual = stat::fstat(book.fd(original)?).map_err(|_| "maintenance-renamed-stat")?;
            let named = book.named(Some(parent),name).map_err(|_| "maintenance-renamed-name")?;
            check(actual.st_flags == 0 && named.st_flags == 0 && Identity::of(&actual) == Identity::of(&named)
                && same_renamed(before,Identity::of(&actual)), "maintenance-renamed-original")?;
            book.originals[original].parent = Some(parent); book.originals[original].name = name.into();
            book.originals[original].identity = Some(Identity::of(&actual));
            let directory = actual.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits();
            book.protected(original,directory,Some(if directory { 0o555 } else { 0o444 }))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "maintenance-renamed-attributes")?;
            book.check_name(original,true)
        }
        struct RenameReturn { returned: ReturnedData, result: Result<()> }
        fn move_app(book: &mut Install, original: usize, from: usize, source: &str, to: usize, destination: &str) -> RenameReturn {
            let mut returned = ReturnedData::KnownRefusal;
            let result = (|| {
                book.clock()?; book.check_name(original,true)?;
                check(book.originals[original].parent == Some(from) && book.originals[original].name == source,
                    "maintenance-move-source")?;
                book.check_name(from,false)?; book.check_name(to,false)?;
                check(book.identity(original)?.dev == book.identity(from)?.dev && book.identity(from)?.dev == book.identity(to)?.dev,
                    "maintenance-move-filesystem")?;
                book.protected(original,true,Some(0o555))?; book.absent(to,destination)?;
                let actual = native::publish_directory(book.fd(from)?.as_fd(),source,book.fd(to)?.as_fd(),destination);
                match actual {
                    Ok(()) => returned = ReturnedData::KnownSuccess,
                    Err(error) => {
                        if error.raw_os_error() != Some(Errno::EEXIST as i32) { returned = ReturnedData::Unknown; book.unknown = true; }
                        return Err("maintenance-exclusive-move");
                    },
                }
                rebind_renamed(book,original,to,destination)?; book.absent(from,source)?;
                book.persist(from,false)?; if from != to { book.persist(to,false)?; }
                book.check_name(original,true)
            })();
            RenameReturn { returned, result }
        }
        fn publish_state(book: &mut Install, observed: &Observed, bytes: Vec<u8>, inverse: bool) -> Result<()> {
            let state = data(StateData::parse_data(&bytes,&observed.selected))?;
            let root = observed.prepared.destination;
            let mut returned = ReturnedData::KnownRefusal;
            let result = (|| {
                book.clock()?;
                let reader = if let Some(history) = &observed.history {
                    held_bytes(book,history.state_original,&history.state_bytes)?;
                    let archive = data(transaction::archived_state_name_data(history.current.state.invocation_data()))?;
                    book.absent(root,&archive)?;
                    let pending = book.record_file(root,&archive,&bytes,Role::ReceiptWriter)?;
                    held_bytes(book,pending,&bytes)?;
                    check(book.identity(pending)?.dev == book.identity(history.state_original)?.dev
                        && book.identity(pending)?.dev == book.identity(root)?.dev
                        && book.identity(pending)?.ino != book.identity(history.state_original)?.ino, "maintenance-state-filesystem")?;
                    book.clock()?;
                    match native::swap_installation_state(book.fd(root)?.as_fd(),&archive) {
                        Ok(()) => {
                            returned = ReturnedData::KnownSuccess;
                            book.maintenance.as_mut().ok_or("maintenance-progress-missing")?.state_published = true;
                        },
                        Err(_) => { book.unknown = true; returned = ReturnedData::Unknown; return Err("maintenance-state-swap"); },
                    }
                    rebind_renamed(book,history.state_original,root,&archive)?;
                    rebind_renamed(book,pending,root,transaction::STATE_NAME)?;
                    held_bytes(book,history.state_original,&history.state_bytes)?; held_bytes(book,pending,&bytes)?;
                    pending
                } else {
                    check(!inverse, "maintenance-inverse-without-history")?;
                    book.absent(root,transaction::STATE_NAME)?;
                    let reader = book.record_file(root,transaction::STATE_NAME,&bytes,Role::ReceiptWriter)?;
                    returned = ReturnedData::KnownSuccess;
                    book.maintenance.as_mut().ok_or("maintenance-progress-missing")?.state_published = true;
                    reader
                };
                book.persist(root,false)?; held_bytes(book,reader,&bytes)?;
                let effects = book.maintenance.as_mut().ok_or("maintenance-progress-missing")?;
                effects.state = Some(state); effects.state_bytes = Some(bytes);
                book.forward_close(reader,"maintenance-state-reader-close")
            })();
            step(book,if inverse { StepData::StateRestored } else { StepData::StatePublished },returned,result,inverse)
        }
        fn generation(book: &Install, observed: &Observed, release: usize, app: usize, instance: &str) -> Result<GenerationData> {
            data(GenerationData::from_original_fields_data(&observed.selected,observed.selected.current_data(),instance,
                book.recorded_directory(release)?,app_identity(book,app)?))
        }
        fn forward(book: &mut Install, observed: &Observed, invocation: &str) -> Result<()> {
            let root = observed.prepared.destination;
            let intent = observed.intent.as_ref().ok_or("maintenance-intent-missing")?;
            if let Some(history) = &observed.history { held_bytes(book,history.state_original,&history.state_bytes)?; }
            held_bytes(book,observed.intent_original.ok_or("maintenance-intent-missing")?,&observed.intent_bytes(invocation, observed.intent.as_ref().ok_or("maintenance-intent-missing")?.request_id_data())?)?;
            if observed.action != ActionData::FreshInstall {
                step(book,StepData::Reobserved,ReturnedData::KnownSuccess,Ok(()),false)?;
            }
            let current = if observed.action == ActionData::SamePackageNoop {
                check(book.payload_write_calls == 0 && book.payload_written == 0, "maintenance-noop-payload")?;
                book.payload_verified = true; // Entire original App/runtime was actually read above.
                observed.history.as_ref().ok_or("maintenance-history-missing")?.current.state.current_data()
            } else {
                let staged = book.stage_payload(&observed.prepared,invocation,observed.action != ActionData::RestoreFixedApp);
                let succeeded = staged.is_ok();
                step(book,StepData::Prepared,if succeeded { ReturnedData::KnownSuccess } else { ReturnedData::KnownRefusal },
                    staged.as_ref().map(|_| ()).map_err(|e| *e),false)?;
                let (stage,app,runtime) = staged?;
                let release = if observed.action == ActionData::RestoreFixedApp {
                    observed.old_release.ok_or("maintenance-generation-missing")?
                } else {
                    book.absent(observed.prepared.versions,paths::RELEASE)?;
                    let release = book.directory(observed.prepared.versions,paths::RELEASE,true,0o755)?;
                    let runtime = runtime.ok_or("stage-missing")?;
                    let published = book.publish(runtime,stage,"runtime",release,"runtime",true);
                    let returned = returned_publication(book,book.runtime_publication);
                    step(book,StepData::RuntimePublished,returned,published,false)?;
                    book.receipt("runtime-publication-confirmed")?;
                    let metadata = book.record_metadata(root,release,invocation,&observed.prepared.inventory_bytes);
                    step(book,StepData::MetadataPublished,if metadata.is_ok() { ReturnedData::KnownSuccess }
                        else { ReturnedData::KnownRefusal },metadata,false)?;
                    release
                };
                if observed.action == ActionData::Update {
                    let old = observed.old_app.ok_or("maintenance-app-missing-or-refused")?;
                    let quarantine = data(transaction::retained_app_name_data(invocation))?;
                    let renamed = move_app(book,old,root,paths::APP_NAME,root,&quarantine);
                    step(book,StepData::OldAppQuarantined,renamed.returned,renamed.result,false)?;
                }
                let published = book.publish(app,stage,"app",root,paths::APP_NAME,false);
                let returned = returned_publication(book,book.app_publication);
                step(book,StepData::AppPublished,returned,published,false)?;
                book.receipt(if observed.action == ActionData::RestoreFixedApp { "app-publication-confirmed" }
                    else { "both-publications-confirmed" })?;
                let instance = if observed.action == ActionData::RestoreFixedApp {
                    observed.history.as_ref().ok_or("maintenance-history-missing")?.current.state.current_data().instance_data().to_owned()
                } else { invocation.to_owned() };
                generation(book,observed,release,app,&instance)?
            };
            let state = data(StateData::encode_applied_data(intent,observed.previous(),&current,&observed.selected))?;
            publish_state(book,observed,state,false)
        }
        fn try_inverse(book: &mut Install, observed: &Observed, invocation: &str) -> Result<()> {
            check(observed.action == ActionData::Update && !book.unknown, "maintenance-inverse-not-eligible")?;
            book.clock()?;
            let history = observed.history.as_ref().ok_or("maintenance-history-missing")?;
            let root = observed.prepared.destination;
            let old = observed.old_app.ok_or("maintenance-app-missing-or-refused")?;
            let stage = book.stage.ok_or("stage-missing")?;
            let quarantine = data(transaction::retained_app_name_data(invocation))?;
            check(book.originals[old].parent == Some(root) && book.originals[old].name == quarantine,
                "maintenance-inverse-original")?;
            book.check_name(old,true)?; held_bytes(book,history.state_original,&history.state_bytes)?;
            book.absent(root,&data(transaction::archived_state_name_data(history.current.state.invocation_data()))?)?;
            let new_published = book.app_publication == "confirmed";
            if new_published {
                let app = book.app.ok_or("stage-missing")?;
                book.check_name(app,true)?; book.absent(stage,"app")?;
            } else { book.absent(root,paths::APP_NAME)?; }
            let (at, uncertain) = timestamp(book);
            check(!uncertain, "maintenance-inverse-clock")?;
            let effects = book.maintenance.as_mut().ok_or("maintenance-progress-missing")?;
            check(!effects.state_published,"maintenance-inverse-after-state")?;
            data(effects.progress.begin_inverse_data(at,true,true))?;
            effects.inverse = true;
            if new_published {
                let app = book.app.ok_or("stage-missing")?;
                let returned = move_app(book,app,root,paths::APP_NAME,stage,"app");
                step(book,StepData::NewAppWithdrawn,returned.returned,returned.result,true)?;
            }
            let returned = move_app(book,old,root,&quarantine,root,paths::APP_NAME);
            step(book,StepData::OldAppRestored,returned.returned,returned.result,true)?;
            let bytes = data(StateData::encode_inverse_data(observed.intent.as_ref().ok_or("maintenance-intent-missing")?,
                (&history.current.state,&history.current.capsule),true,book.runtime_publication == "confirmed",&observed.selected))?;
            publish_state(book,observed,bytes,true)
        }
        pub(super) fn execute(book: &mut Install, observed: Observed, invocation: &str) -> Result<()> {
            check(book.worker_stderr_is_gate && book.worker_go_eof && book.maintenance.is_none(), "maintenance-original-go-required")?;
            book.registration_ready()?;
            let deadline = book.worker_deadline.as_ref().ok_or("worker-clock-missing")?;
            let at = deadline.check_work()?;
            let progress = data(ProgressData::new_data(observed.action,at,deadline.original_endpoint()))?;
            book.maintenance = Some(Effects { action:observed.action,progress,state:None,state_bytes:None,state_published:false,inverse:false });
            let result = forward(book,&observed,invocation);
            if let Err(error) = result {
                let (at, uncertain) = timestamp(book);
                if uncertain { book.unknown = true; }
                if let Some(effects) = book.maintenance.as_mut() {
                    let _ = effects.progress.stop_data(if book.unknown { ReturnedData::Unknown } else { ReturnedData::KnownRefusal },at);
                }
                // A failure may allow ONE known inverse under the same original
                // gate/objects/time. Never erase the original failure or leftovers.
                if observed.action == ActionData::Update { let _ = try_inverse(book,&observed,invocation); }
                return Err(error);
            }
            Ok(())
        }
        pub(super) fn state_after_join(book: &mut Install, observed: &Observed, invocation: &str,
            reported_bytes: Option<&str>, inverse: bool) -> Result<Option<StateData>> {
            let Some(reported) = reported_bytes else { return Ok(None); };
            let (reader, bytes) = metadata_original(book,observed.prepared.destination,transaction::STATE_NAME,transaction::STATE_LIMIT)?;
            check(bytes == reported.as_bytes(),"maintenance-parent-state-readback")?;
            let state = data(StateData::parse_data(&bytes,&observed.selected))?;
            check(state.invocation_data() == invocation,"maintenance-parent-state-invocation")?;
            let intent = observed.intent.as_ref().ok_or("maintenance-intent-missing")?;
            let reproduced = if inverse {
                data(StateData::encode_inverse_data(intent,observed.previous().ok_or("maintenance-history-missing")?,true,true,&observed.selected))?
            } else { data(StateData::encode_applied_data(intent,observed.previous(),&state.current_data(),&observed.selected))? };
            check(reproduced == bytes,"maintenance-parent-state-transition")?;
            if let Some(history) = &observed.history {
                let archive = data(transaction::archived_state_name_data(history.current.state.invocation_data()))?;
                rebind_renamed(book,history.state_original,observed.prepared.destination,&archive)?;
                held_bytes(book,history.state_original,&history.state_bytes)?;
            }
            if observed.action == ActionData::Update {
                let old = observed.old_app.ok_or("maintenance-app-missing-or-refused")?;
                let name = if inverse { paths::APP_NAME.to_owned() } else { data(transaction::retained_app_name_data(invocation))? };
                rebind_renamed(book,old,observed.prepared.destination,&name)?;
                check(app_identity(book,old)? == observed.history.as_ref().ok_or("maintenance-history-missing")?
                    .current.state.current_data().app_identity_data(),"maintenance-parent-old-app")?;
            }
            // Fresh originals, exact descriptor and complete current payload;
            // never make a worker-selected tuple the parent's expected release.
            let _ = audit_generation(book,observed.prepared.destination,observed.prepared.versions,
                &state.current_data(),false,false)?;
            held_bytes(book,reader,&bytes)?;
            book.forward_close(reader,"maintenance-parent-state-close")?; Ok(Some(state))
        }
        pub(super) fn persist_capsule(book: &mut Install, observed: &Observed, invocation: &str, bytes: &[u8]) -> Result<()> {
            check(bytes.len() <= transaction::CAPSULE_LIMIT,"maintenance-capsule-bound")?;
            let parsed = data(CapsuleData::parse_data(bytes,&observed.selected))?;
            check(parsed.invocation_data() == invocation,"maintenance-capsule-invocation")?;
            let reader = book.record_file(observed.prepared.destination,&data(transaction::capsule_name_data(invocation))?,bytes,Role::ReceiptWriter)?;
            book.persist(observed.prepared.destination,false)?; held_bytes(book,reader,bytes)?;
            book.forward_close(reader,"maintenance-capsule-close")
        }
        pub(super) fn finish(book: &mut Install, result: Result<()>, settled: bool, timely: bool) -> FinalResult {
            let (at, uncertain) = timestamp(book);
            if uncertain { book.unknown = true; }
            // The close observation itself must still precede the ORIGINAL
            // endpoint; a prior successful checkpoint is not a lease.
            let timely = timely && !uncertain && book.worker_deadline.as_ref()
                .is_some_and(|clock| at < clock.original_endpoint());
            let Some(effects) = book.maintenance.as_mut() else {
                return final_result_after_deadline(Err("maintenance-progress-missing"),settled,true,
                    book.runtime_publication,book.app_publication,timely);
            };
            let returned = if settled && !uncertain { ReturnedData::KnownSuccess } else { ReturnedData::Unknown };
            if effects.inverse { let _ = effects.progress.inverse_return_data(StepData::OriginalsSettled,returned,at); }
            else { let _ = effects.progress.forward_return_data(StepData::OriginalsSettled,returned,at); }
            let reason = result.err().or_else(|| (!settled).then_some("original-close-unknown"))
                .or_else(|| (!timely).then_some("deadline"));
            let progress = effects.progress.outcome_data();
            let complete = reason.is_none() && settled && timely && !book.unknown && progress == ProgressOutcomeData::Recorded
                && effects.state_published && effects.state.is_some();
            let inverse = reason.is_some() && settled && timely && !book.unknown && progress == ProgressOutcomeData::InverseRecorded
                && effects.state_published && effects.state.is_some();
            let published = book.runtime_publication == "confirmed" || book.app_publication == "confirmed" || effects.state_published;
            let state = if complete { match effects.action { ActionData::SamePackageNoop => "same-package",
                ActionData::RestoreFixedApp => "restored-app", _ => "installed" } }
                else if inverse { "inverse-recorded" } else if published { "partial-installation-retained" }
                else if book.unknown || progress == ProgressOutcomeData::Unknown { "unknown-retained" } else { "refused-staging-retained" };
            FinalResult { state,reason,exit:if complete { 0 } else if published || inverse { 20 } else { 1 },deadline_met:timely }
        }
    }

    #[allow(dead_code)]
    // The complete outer package is input DATA. The source-selected signature,
    // fixed current-code purpose and compiled tuple, not this path or mount,
    // establish producer authority in the original Parent before GO.
    mod completed_package {
        use super::*;
        use mobile_release_desktop::macos_install_producer::{DESCRIPTOR_FILENAME, SIGNATURE_FILENAME,
            DESCRIPTOR_LIMIT, SIGNATURE_LIMIT};
        use nix::sys::uio::pread;

        // Internal callers select a purpose BEFORE reading untrusted names or
        // descriptor bytes. This selects an input grammar, never signature or
        // installed-code authority. The ordinary Install path is unchanged.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum InputPurpose { Install, Remove }
        impl InputPurpose {
            fn request_id(self, name: &str) -> Result<Option<String>> {
                match self {
                    Self::Install => transaction::request_from_package_name_data(name)
                        .map_err(|_| "producer-package-name"),
                    Self::Remove => {
                        check(name == "Remove.pkg", "producer-package-name")?;
                        Ok(None)
                    },
                }
            }
            fn descriptor_name(self) -> &'static str {
                match self {
                    Self::Install => DESCRIPTOR_FILENAME,
                    Self::Remove => mobile_release_desktop::macos_remove_producer::DESCRIPTOR_FILENAME,
                }
            }
            fn signature_name(self) -> &'static str {
                match self {
                    Self::Install => SIGNATURE_FILENAME,
                    Self::Remove => mobile_release_desktop::macos_remove_producer::SIGNATURE_FILENAME,
                }
            }
            fn descriptor_limit(self) -> usize {
                match self {
                    Self::Install => DESCRIPTOR_LIMIT,
                    Self::Remove => mobile_release_desktop::macos_remove_producer::DESCRIPTOR_LIMIT,
                }
            }
            fn signature_limit(self) -> usize {
                // The actual Remove verifier accepts only RSA signatures of
                // 256/384/512 bytes. Do not widen ordinary Install's old limit.
                match self { Self::Install => SIGNATURE_LIMIT, Self::Remove => 512 }
            }
        }

        #[derive(Clone, PartialEq, Eq)]
        struct MountData { id: statfs::fsid_t, flags: MntFlags, kind: String, device: i64 }
        impl MountData {
            fn read(book: &Install, original: usize) -> Result<Self> {
                book.clock()?;
                let fs = statfs::fstatfs(book.fd(original)?).map_err(|_| "producer-source-mount")?;
                let value = Self { id:fs.filesystem_id(),flags:fs.flags(),
                    kind:fs.filesystem_type_name().into(),device:book.identity(original)?.dev };
                book.clock()?;
                Ok(value)
            }
            fn same_mount(&self, other: &Self) -> bool { self == other }
        }
        fn readonly_distribution(kind: &str, flags: MntFlags) -> bool {
            matches!(kind,"apfs"|"hfs") && flags.contains(MntFlags::MNT_LOCAL | MntFlags::MNT_RDONLY)
                && !flags.intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED)
        }
        fn source_component(value: &str) -> bool {
            // The native DMG title can contain single spaces (and macOS may
            // append a space plus mount collision number). This is not a
            // payload-relative entry: keep its bounded component grammar local.
            value.len() <= 255 && value.split(' ').all(component)
        }
        fn source_name(path: &str) -> Result<(&str, Vec<&str>)> {
            source_name_for(path, InputPurpose::Install)
        }
        fn source_name_for(path: &str, purpose: InputPurpose) -> Result<(&str, Vec<&str>)> {
            check(path.starts_with('/') && path.len() <= 4096
                && path[1..].split('/').count() <= 32, "producer-source-spelling")?;
            let mut parts: Vec<_> = path[1..].split('/').collect();
            check(parts.len() >= 2 && parts.iter().all(|name| source_component(name)), "producer-source-spelling")?;
            let name = parts.pop().ok_or("producer-package-name")?;
            purpose.request_id(name)?;
            Ok((name,parts))
        }
        // Offset reads retain this SAME held original and never reset or share
        // an OFD position. Complete EOF/count plus named/held POST are required.
        // For the package, retain only the four-byte XAR spelling, not its body.
        fn original_bytes(book: &Install, original: usize, limit: usize, collect: bool) -> Result<(String,Vec<u8>)> {
            book.check_name(original,true)?;
            let size = usize::try_from(book.identity(original)?.size).map_err(|_| "producer-source-size")?;
            check(size > 0 && size <= limit && limit as u64 <= installation_record::PAYLOAD_LIMIT
                && (!collect || limit <= DESCRIPTOR_LIMIT), "producer-source-size")?;
            let mut digest = Sha256::new(); let mut bytes = Vec::new();
            let mut offset = 0usize; let mut block = [0u8;65536];
            loop {
                book.clock()?;
                let used = match pread(book.fd(original)?,&mut block,offset as i64) {
                    Ok(used) => used, Err(Errno::EINTR) => continue,
                    Err(_) => return Err("producer-source-read"),
                };
                book.clock()?;
                if used == 0 { break; }
                check(used <= block.len(),"producer-source-read")?;
                offset = offset.checked_add(used).ok_or("producer-source-size")?;
                check(offset <= size,"producer-source-size")?;
                digest.update(&block[..used]);
                if collect { bytes.extend_from_slice(&block[..used]); }
                else if bytes.len() < 4 { bytes.extend_from_slice(&block[..used.min(4-bytes.len())]); }
            }
            check(offset == size,"producer-source-size")?; book.check_name(original,true)?;
            Ok((digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect(),bytes))
        }
        struct Held { original: usize, mount: MountData, readonly: bool, directory: bool }
        impl Held {
            fn post(&self, book: &Install) -> Result<()> {
                book.check_name(self.original,true)?;
                check(MountData::read(book,self.original)? == self.mount,"producer-source-mount-changed")?;
                if self.readonly {
                    check(readonly_distribution(&self.mount.kind,self.mount.flags),"producer-distribution-writable")?;
                    // A read-only mounted distribution is not represented as
                    // UID0 ownership or as a producer signature. Existing ACLs,
                    // quarantine and files are neither modified nor erased.
                    let id = book.identity(self.original)?;
                    check(id.mode & 0o170000 == if self.directory { 0o040000 } else { 0o100000 }
                        && (self.directory || id.links == 1),"producer-source-shape")
                } else { book.protected(self.original,self.directory,None) }
            }
        }
        pub(super) struct Input {
            purpose: InputPurpose,
            held: Vec<Held>, package: usize, descriptor: usize, signature: usize,
            package_sha256: String, descriptor_sha256: String, signature_sha256: String,
            descriptor_body: Vec<u8>, signature_body: Vec<u8>, requested_id: Option<String>,
        }
        impl Input {
            pub(super) fn open(book: &mut Install, completed_path: &str) -> Result<Self> {
                Self::open_for(book, completed_path, InputPurpose::Install)
            }
            // Deliberately not dispatched until the Parent's separate Remove
            // signature/current-source/peer/exclusion composition is admitted.
            pub(super) fn open_removal(book: &mut Install, completed_path: &str) -> Result<Self> {
                Self::open_for(book, completed_path, InputPurpose::Remove)
            }
            fn open_for(book: &mut Install, completed_path: &str, purpose: InputPurpose) -> Result<Self> {
                // The caller must already have admitted the fixed extracted
                // SOURCE and self image; no argument alone grants this role.
                book.clock()?;
                let (name,parts) = source_name_for(completed_path,purpose)?;
                let mut directories = Vec::new();
                let mut parent = book.open(None,"/",true)?; directories.push(parent);
                for part in parts { parent=book.open(Some(parent),part,true)?; directories.push(parent); }
                let destination_mount=MountData::read(book,parent)?;
                let readonly=readonly_distribution(&destination_mount.kind,destination_mount.flags);
                let mut entered_distribution=false; let mut held=Vec::new();
                for original in directories {
                    let mount=MountData::read(book,original)?;
                    let on_distribution=readonly && mount.same_mount(&destination_mount);
                    check(!entered_distribution || on_distribution,"producer-distribution-cross-mount")?;
                    entered_distribution |= on_distribution;
                    let value=Held { original,mount,readonly:on_distribution,directory:true };
                    value.post(book)?;held.push(value);
                }
                check(!readonly || entered_distribution,"producer-distribution-missing")?;
                let mut open_file=|file_name: &str| -> Result<usize> {
                    let original=book.open(Some(parent),file_name,false)?;
                    let mount=MountData::read(book,original)?;
                    check(mount.same_mount(&destination_mount),"producer-file-cross-mount")?;
                    let value=Held { original,mount,readonly,directory:false };
                    value.post(book)?;held.push(value);Ok(original)
                };
                let package=open_file(name)?;
                let descriptor=open_file(purpose.descriptor_name())?;
                let signature=open_file(purpose.signature_name())?;
                drop(open_file); // No retained mutable book borrow across reads.
                let (package_sha256,prefix)=original_bytes(book,package,installation_record::PAYLOAD_LIMIT as usize,false)?;
                check(book.identity(package)?.size >= 28 && prefix == b"xar!","producer-completed-package")?;
                let (descriptor_sha256,descriptor_body)=original_bytes(book,descriptor,purpose.descriptor_limit(),true)?;
                let (signature_sha256,signature_body)=original_bytes(book,signature,purpose.signature_limit(),true)?;
                let requested_id=purpose.request_id(name)?;
                let input=Self { purpose,held,package,descriptor,signature,package_sha256,descriptor_sha256,signature_sha256,
                    descriptor_body,signature_body,requested_id };
                input.post(book)?;Ok(input)
            }
            pub(super) fn post(&self, book: &Install) -> Result<()> {
                book.clock()?;
                for held in &self.held { held.post(book)?; }
                book.clock()
            }
            pub(super) fn content_post(&self, book: &Install) -> Result<()> {
                self.post(book)?;
                let (package,prefix)=original_bytes(book,self.package,installation_record::PAYLOAD_LIMIT as usize,false)?;
                let (descriptor,body)=original_bytes(book,self.descriptor,self.purpose.descriptor_limit(),true)?;
                let (signature,sign)=original_bytes(book,self.signature,self.purpose.signature_limit(),true)?;
                check(package==self.package_sha256 && prefix==b"xar!" && descriptor==self.descriptor_sha256
                    && body==self.descriptor_body && signature==self.signature_sha256 && sign==self.signature_body,
                    "producer-original-content-changed")?;
                self.post(book)
            }
            // Indices into the SAME Book only; no cloned signature authority.
            pub(super) fn removal_signed_originals_data(&self)->Result<[usize;2]> {
                check(matches!(self.purpose,InputPurpose::Remove),"removal-snapshot-input-purpose")?;
                Ok([self.descriptor,self.signature])
            }
            pub(super) fn retained_bytes_data(&self)->Result<usize> {
                let mut count=std::mem::size_of::<Self>().checked_add(self.held.capacity().checked_mul(std::mem::size_of::<Held>()).ok_or("producer-source-memory")?)
                    .and_then(|n|n.checked_add(self.package_sha256.capacity()+self.descriptor_sha256.capacity()+self.signature_sha256.capacity()))
                    .and_then(|n|n.checked_add(self.descriptor_body.capacity()+self.signature_body.capacity()))
                    .and_then(|n|n.checked_add(self.requested_id.as_ref().map_or(0,String::capacity))).ok_or("producer-source-memory")?;
                for held in &self.held{count=count.checked_add(held.mount.kind.capacity()).ok_or("producer-source-memory")?;}
                Ok(count)
            }
            pub(super) fn descriptor_data(&self) -> &[u8] { &self.descriptor_body }
            pub(super) fn signature_data(&self) -> &[u8] { &self.signature_body }
            pub(super) fn package_sha256_data(&self) -> &str { &self.package_sha256 }
            pub(super) fn request_id_data(&self) -> Option<&str> { self.requested_id.as_deref() }
        }
        #[cfg(test)]
        pub(super) fn fixed_source_data_checks() {
            let local=MntFlags::MNT_LOCAL;let readonly=MntFlags::MNT_RDONLY;
            assert!(readonly_distribution("apfs",local|readonly));
            assert!(readonly_distribution("hfs",local|readonly|MntFlags::MNT_IGNORE_OWNERSHIP));
            for flags in [local,readonly,local|readonly|MntFlags::MNT_UNION,local|readonly|MntFlags::MNT_AUTOMOUNTED] {
                assert!(!readonly_distribution("apfs",flags));
            }
            for kind in ["nfs","smbfs","autofs",""] { assert!(!readonly_distribution(kind,local|readonly)); }
            assert!(source_name("/Volumes/Mobile Release Kit/Install.pkg").is_ok());
            assert!(source_name("/Volumes/Mobile Release Kit 1/Install.pkg").is_ok());
            for name in ["", ".", "..", " name", "name ", "double  space", "line\nfeed", "tab\tname", "non-ascii-é"] {
                assert!(!source_component(name));
            }
            assert!(!source_component(&"a".repeat(256)));
            assert!(source_name("/root-owned/MobileReleaseKit-Request-11111111111111111111111111111111.pkg").is_ok());
            for path in ["Install.pkg","/Install.pkg","/Volumes/../Install.pkg","/Volumes/a//Install.pkg",
                "/Volumes/a/Other.pkg","/Volumes/a/Install.pkg/","/Volumes/a/Install.pkg\0"] {
                assert!(source_name(path).is_err());
            }
            // These checks establish closed grammar/bounds only. They do NOT
            // substitute parsed DATA for native package or signing admission.
            let removal = InputPurpose::Remove;
            assert_eq!(source_name_for("/Volumes/Mobile Release Kit Remove/Remove.pkg",removal)
                .unwrap().0,"Remove.pkg");
            assert_eq!(removal.request_id("Remove.pkg"),Ok(None));
            assert!(source_name("/Volumes/Mobile Release Kit Remove/Remove.pkg").is_err());
            for name in ["Install.pkg","producer.json","remove-producer.json",
                "MobileReleaseKit-Request-11111111111111111111111111111111.pkg","remove.pkg"] {
                assert!(source_name_for(&format!("/Volumes/Removal/{name}"),removal).is_err());
            }
            for path in ["Remove.pkg","/Remove.pkg","/Volumes/../Remove.pkg","/Volumes/a//Remove.pkg",
                "/Volumes/a/Remove.pkg/","/Volumes/a/Remove.pkg\0"] {
                assert!(source_name_for(path,removal).is_err());
            }
            assert_eq!(removal.descriptor_name(),"remove-producer.json");
            assert_eq!(removal.signature_name(),"remove-producer.sig");
            assert_eq!(removal.descriptor_limit(),16*1024);
            assert_eq!(removal.signature_limit(),512);
            assert_eq!(InputPurpose::Install.descriptor_name(),DESCRIPTOR_FILENAME);
            assert_eq!(InputPurpose::Install.signature_name(),SIGNATURE_FILENAME);
            assert_eq!(InputPurpose::Install.descriptor_limit(),DESCRIPTOR_LIMIT);
            assert_eq!(InputPurpose::Install.signature_limit(),SIGNATURE_LIMIT);
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
        // Same 16MiB containing reservation, not an additional budget. Includes
        // shared request/raw encoding, its native binding and frame copies.
        const REMOVAL_REQUEST_RESERVE: usize = 256 * 1024;
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
            fn from_entry(start: u64) -> Result<Self> {
                let end = start.checked_add(TOTAL).ok_or("worker-clock-value")?;
                let deadline = Self { start, end, last: Cell::new(start), unknown: Cell::new(false) };
                deadline.check_work()?; Ok(deadline)
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
            pub(super) fn original_endpoint(&self) -> u64 { self.end }
            // Accounting for a call which has ALREADY returned: report its real
            // timestamp even if late; this never authorizes another work call.
            pub(super) fn returned_time(&self) -> (u64, bool) {
                match monotonic() {
                    Ok(now) => {
                        let uncertain = self.unknown.get() || now < self.last.get() || now < self.start;
                        self.last.set(self.last.get().max(now));
                        if uncertain { self.unknown.set(true); }
                        (now,uncertain)
                    },
                    Err(_) => { self.unknown.set(true); (self.last.get(),true) },
                }
            }
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
                    removal_live_reserved:0,removal_control_reserved:0,removal_snapshot_capture:None,removal_snapshot_work_reserved:false,removal_payload_plan:None,removal_observation_control:None,removal_observation_reserved:0,removal_archive_scan:None,
                    payload_written:0,payload_write_calls:0,
                    stage:None,stage_name:None,app:None,runtime:None,runtime_publication:"not-attempted",
                    app_publication:"not-attempted",payload_verified:false,
                    metadata:installation_record::Progress::default(),gate:MaintenanceGate::new(),registration:RegistrationReservation::new(),maintenance:None,
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
        pub(super) fn identity_data(id: Identity) -> Value {
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
            "receipt-shape", "refused-staging-retained",
            "registration-attributes", "registration-busy-or-refused", "registration-close-unknown", "registration-closed-original",
            "registration-content", "registration-created-correspondence", "registration-finality-missing", "registration-maintenance-required",
            "registration-name-refused", "registration-order", "registration-original", "registration-predecessor-required",
            "registration-shape", "registration-stat", "registration-worker-go", "registration-write-bound",
            "runtime-publication-collision", "runtime-publication-confirmed",
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
        struct MaintenanceReply {
            action: ActionData, progress: String, state_published: bool, state_bytes: Option<String>, inverse: bool,
        }
        impl MaintenanceReply {
            fn from_original(effects: &maintenance::Effects) -> Self {
                let progress = match effects.progress.outcome_data() {
                    transaction::ProgressOutcomeData::InProgress => "in-progress",
                    transaction::ProgressOutcomeData::Recorded => "recorded",
                    transaction::ProgressOutcomeData::Refused => "refused",
                    transaction::ProgressOutcomeData::Unknown => "unknown",
                    transaction::ProgressOutcomeData::InverseRecorded => "inverse-recorded",
                };
                Self { action:effects.action,progress:progress.into(),state_published:effects.state_published,
                    // The encoder emitted UTF-8 JSON. If its storage is invalid,
                    // omit it and fail the result predicate; never lossy-decode.
                    state_bytes:effects.state_bytes.as_ref().and_then(|b| std::str::from_utf8(b).ok()).map(str::to_owned),
                    inverse:effects.inverse }
            }
            fn data(&self) -> Value {
                json!({"action":self.action,"progress":self.progress,"statePublished":self.state_published,
                    "stateBytes":self.state_bytes,"inverseStarted":self.inverse})
            }
            fn parse(value: &Value) -> Result<Self> {
                object(value,&["action","progress","statePublished","stateBytes","inverseStarted"])?;
                let action: ActionData = serde_json::from_value(value["action"].clone()).map_err(|_| "maintenance-result-shape")?;
                check(action != ActionData::Uninstall,"maintenance-result-shape")?;
                let progress = value["progress"].as_str().ok_or("maintenance-result-shape")?;
                check(matches!(progress,"in-progress" | "recorded" | "refused" | "unknown" | "inverse-recorded"),
                    "maintenance-result-shape")?;
                let state_published = value["statePublished"].as_bool().ok_or("maintenance-result-shape")?;
                let state_bytes = if value["stateBytes"].is_null() { None } else {
                    let text = value["stateBytes"].as_str().ok_or("maintenance-result-shape")?;
                    check(state_published && !text.is_empty() && text.len() <= transaction::STATE_LIMIT,
                        "maintenance-result-bound")?;
                    Some(text.to_owned())
                };
                let inverse = value["inverseStarted"].as_bool().ok_or("maintenance-result-shape")?;
                check(!inverse || action == ActionData::Update,"maintenance-result-shape")?;
                Ok(Self { action,progress:progress.into(),state_published,state_bytes,inverse })
            }
            fn accepts(&self, returned: &PreExit) -> bool {
                let published = returned.runtime == "confirmed" || returned.app == "confirmed" || self.state_published;
                let finality = returned.originals && returned.payload && returned.verified && returned.timely && !returned.unknown;
                let committed = self.progress == "recorded" && self.state_published && self.state_bytes.is_some() && !self.inverse;
                matches!(returned.exit,0 | 1 | 20) && returned.bytes <= installation_record::PAYLOAD_LIMIT
                    && (returned.writes == 0) == (returned.bytes == 0) && returned.writes <= returned.bytes
                    && (!returned.originals || returned.payload)
                    && match returned.state.as_str() {
                        "installed" => returned.exit == 0 && finality && committed && returned.writes > 0
                            && matches!(self.action,ActionData::FreshInstall | ActionData::Update)
                            && returned.runtime == "confirmed" && returned.app == "confirmed",
                        "same-package" => returned.exit == 0 && finality && committed && self.action == ActionData::SamePackageNoop
                            && returned.writes == 0 && returned.runtime == "not-attempted" && returned.app == "not-attempted",
                        "restored-app" => returned.exit == 0 && finality && committed && self.action == ActionData::RestoreFixedApp
                            && returned.writes > 0 && returned.runtime == "not-attempted" && returned.app == "confirmed",
                        "inverse-recorded" => returned.exit == 20 && finality && self.action == ActionData::Update && self.inverse
                            && self.progress == "inverse-recorded" && self.state_published && self.state_bytes.is_some()
                            && returned.writes > 0 && returned.runtime == "confirmed",
                        "partial-installation-retained" => returned.exit == 20 && published,
                        "unknown-retained" => returned.exit == 1 && !published && (returned.unknown || self.progress == "unknown"),
                        "refused-staging-retained" => returned.exit == 1 && !published && !returned.unknown && self.progress != "unknown",
                        _ => false,
                    }
            }
        }
        struct PreExit {
            exit: i32, state: String, originals: bool, payload: bool, verified: bool,
            runtime: String, app: String, timely: bool, unknown: bool, writes: u64, bytes: u64,
            reason: Option<String>, maintenance: Option<MaintenanceReply>,
        }
        impl PreExit {
            fn from_original(book: &Install, result: &FinalResult) -> Self {
                Self { exit:result.exit,state:result.state.into(),originals:book.originals_settled(),
                    payload:book.payload_writers_settled(),verified:book.payload_verified,
                    runtime:book.runtime_publication.into(),app:book.app_publication.into(),
                    timely:result.deadline_met,unknown:book.unknown || book.worker_deadline.as_ref().is_some_and(Deadline::is_unknown),
                    writes:book.payload_write_calls,bytes:book.payload_written,
                    reason:result.reason.map(|label| closed_reason(label).to_owned()),
                    maintenance:book.maintenance.as_ref().map(MaintenanceReply::from_original) }
            }
            fn data(&self, invocation: &str, init_sha: &str) -> Value {
                let mut value = json!({"schemaVersion":2,"kind":"pre-exit-writer-result","invocation":invocation,"initSha256":init_sha,
                    "exitCode":self.exit,"state":self.state,"reason":self.reason,"originalsClosed":self.originals,"payloadClosed":self.payload,
                    "payloadVerified":self.verified,"runtimePublication":self.runtime,"appPublication":self.app,
                    "withinOriginalDeadline":self.timely,"unknown":self.unknown,
                    "payloadWriteCount":self.writes,"payloadWriteBytes":self.bytes,
                    "stdoutClosed":false,"inheritedGateClosed":false,"selfJoined":false});
                if let Some(maintenance) = &self.maintenance { value["maintenance"] = maintenance.data(); }
                value
            }
            fn parse(value: &Value, invocation: &str, init_sha: &str) -> Result<Self> {
                let mut keys = vec!["schemaVersion","kind","invocation","initSha256","exitCode","state","reason","originalsClosed",
                    "payloadClosed","payloadVerified","runtimePublication","appPublication","withinOriginalDeadline",
                    "unknown","payloadWriteCount","payloadWriteBytes","stdoutClosed","inheritedGateClosed","selfJoined"];
                let maintenance = if let Some(value) = value.get("maintenance") {
                    keys.push("maintenance"); Some(MaintenanceReply::parse(value)?)
                } else { None };
                object(value,&keys)?;
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
                    reason:if value["reason"].is_null() { None } else { Some(text("reason")?) },maintenance };
                check(result.reason.as_deref().is_none_or(|label| closed_reason(label) == label)
                    && (result.exit != 0 || result.reason.is_none()), "worker-result-reason")?;
                for publication in [&result.runtime,&result.app] {
                    check(matches!(publication.as_str(), "not-attempted" | "attempting" | "confirmed" | "occupied-refused" | "unknown"),
                        "worker-result-shape")?;
                }
                check(match &result.maintenance {
                    Some(maintenance) => maintenance.accepts(&result),
                    None => outcome_data(result.exit,&result.state,result.originals,result.payload,result.verified,
                        &result.runtime,&result.app,result.timely,result.unknown,result.writes,result.bytes),
                }, "worker-result-shape")?;
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
        // No second output owner, timeout, or per-release shared filename.
        // The original Parent book retains this exact exclusive writer before
        // intent/GO; a failed attempt leaves its own pending file, never removes
        // or overwrites another request's result. All bytes remain provisional
        // until the outer original Installer return is independently observed.
        struct RequestExport {
            request_id: String, name: String, support: usize, writer: usize,
            attempted: bool, sealed_record: bool,
        }
        impl RequestExport {
            fn reserve(book: &mut Install, destination: usize, request_id: &str) -> Result<Self> {
                let name = transaction::export_name_data(request_id).map_err(|_| "maintenance-request-shape")?;
                let support = book.originals[destination].parent.ok_or("maintenance-request-parent")?;
                check(book.originals[destination].name == "MobileReleaseKit"
                    && book.originals[support].name == "Application Support", "maintenance-request-parent")?;
                book.check_name(support, false)?;
                book.protected_as(support,true,None,AclRole::SystemSupport)?;
                let writer = book.create_file(support,&name,Role::ReceiptWriter)?;
                Ok(Self { request_id:request_id.into(),name,support,writer,attempted:false,sealed_record:false })
            }
            fn empty_original(&self, book: &Install) -> Result<()> {
                check(!self.attempted && !self.sealed_record, "maintenance-request-once")?;
                book.check_name(self.support,false)?; book.check_name(self.writer,true)?;
                book.protected(self.writer,false,Some(0o600))?;
                let actual = stat::fstat(book.fd(self.writer)?).map_err(|_| "maintenance-request-stat")?;
                check(actual.st_size == 0 && actual.st_flags == 0, "maintenance-request-empty")?;
                native::no_xattrs(book.fd(self.writer)?.as_fd()).map_err(|_| "maintenance-request-attributes")?;
                book.clock()
            }
            fn persist_reservation(&self, book: &mut Install) -> Result<()> {
                self.empty_original(book)?; book.persist(self.writer,true)?;
                book.persist(self.support,false)?; self.empty_original(book)
            }
            fn publish(&mut self, book: &mut Install, record: &Value) -> Result<()> {
                self.empty_original(book)?;
                check(record["schemaVersion"] == 2 && record["kind"] == "maintenance-parent-pending-finalization"
                    && record["requestId"].as_str() == Some(self.request_id.as_str())
                    && record["resultName"].as_str() == Some(self.name.as_str())
                    && record["originalWriterJoined"] == true
                    && record["parentFinality"] == "pending-original-closes-and-outer-return",
                    "maintenance-request-record")?;
                let mut bytes = ExportBytes(Vec::with_capacity(EXPORT_LIMIT));
                serde_json::to_writer(&mut bytes,record).map_err(|_| "maintenance-request-record")?;
                bytes.0.push(b'\n');
                check(!bytes.0.is_empty() && bytes.0.len() <= EXPORT_LIMIT, "maintenance-request-bound")?;
                self.attempted = true; // No retry even after a partial returned write.
                let reader = book.record_reserved_file(self.writer,&bytes.0)?;
                book.persist(self.support,false)?;
                book.forward_close(reader,"maintenance-request-readback-close")?;
                self.sealed_record = true;
                book.clock()
            }
        }
        // These wrappers stay in the original Parent, before their first call.
        // No parsed descriptor, read-only mount or caller boolean constructs a
        // positive result. Native unknown custody survives to process exit.
        struct ProducerAdmission {
            input: completed_package::Input,
            signature: native::install_producer::ProducerVerifier,
            entry: native::install_producer::CurrentProductVerifier,
            payload: native::install_producer::CurrentProductVerifier,
            code_chain: [usize;4], outer_path: String,
            signature_result: Option<native::install_producer::SignatureResult>,
            entry_result: Option<native::install_producer::CurrentProductResult>,
            payload_result: Option<native::install_producer::CurrentProductResult>,
            descriptor: Option<mobile_release_desktop::macos_install_producer::ProducerData>,
            first: Option<&'static str>,
        }
        fn producer_phase(point: native::install_producer::ProducerCheckpoint)
            -> (native::install_producer::ProducerPhase, native::install_producer::ProducerCustody) {
            use native::install_producer::ProducerCheckpoint;
            match point {
                ProducerCheckpoint::Before{phase,custody} | ProducerCheckpoint::Returned{phase,custody,..} => (phase,custody),
            }
        }
        fn producer_cleanup_point(book: &Install, point: native::install_producer::ProducerCheckpoint)
            -> native::android_service_management::Decision {
            use native::android_service_management::Decision;
            let (phase,custody) = producer_phase(point);
            if !phase.is_cleanup() || custody.unknown { return Decision::Unknown; }
            match book.shared_deadline() {
                Ok(clock) if clock.check_total().is_ok() => Decision::Proceed,
                Ok(clock) if !clock.is_unknown() => Decision::Stop,
                _ => Decision::Unknown,
            }
        }
        fn producer_original_post(book: &Install, source: &Source, input: &completed_package::Input,
            code_chain: &[usize;4]) -> Result<()> {
            book.source_post(source)?;
            input.post(book)?;
            for original in code_chain {
                book.check_name(*original,true)?;
                book.protected_as(*original,true,Some(0o555),AclRole::InputDirectory)?;
            }
            book.clock()
        }
        fn producer_point(book: &Install, source: &Source, input: &completed_package::Input,
            code_chain: &[usize;4], first: &mut Option<&'static str>,
            point: native::install_producer::ProducerCheckpoint) -> native::android_service_management::Decision {
            use native::android_service_management::Decision;
            let (phase,custody) = producer_phase(point);
            // A returned Instant is not a CLOCK_MONOTONIC integer. The native
            // adapter records that real return; we independently sample THIS
            // original parent clock before/after each synchronous native phase.
            if phase.is_cleanup() { return producer_cleanup_point(book,point); }
            if custody.unknown { first.get_or_insert("producer-native-custody-unknown"); return Decision::Unknown; }
            if first.is_some() { return Decision::Stop; }
            if let Err(error) = producer_original_post(book,source,input,code_chain) {
                first.get_or_insert(error);
                return if book.shared_deadline().is_ok_and(Deadline::is_unknown) { Decision::Unknown }
                    else { Decision::Stop };
            }
            Decision::Proceed
        }
        fn producer_policy_matches_data(policy: &mobile_release_desktop::macos_install_producer::SigningPolicyData,
            team: &[u8;10], sha1: &[u8;20], sha256: &[u8;32]) -> bool {
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            policy.team_identifier_data().as_bytes() == team
                && policy.leaf_certificate_sha1_data() == hex(sha1)
                && policy.leaf_certificate_sha256_data() == hex(sha256)
                && policy.requires_hardened_runtime_data() && policy.requires_empty_entitlements_data()
        }
        impl ProducerAdmission {
            fn new(book: &mut Install, source: &Source, completed_path: &str) -> Result<Self> {
                use native::install_producer::{ProducerVerifier,CurrentProductVerifier,CurrentProductRole};
                book.source_post(source)?;
                let input = completed_package::Input::open(book,completed_path)?;
                let outer_path = format!("{}/app",source.source);
                check(outer_path.len() < 1024,"producer-code-path-bound")?;
                let outer = book.open(Some(source.input),"app",true)?;
                let contents = book.open(Some(outer),"Contents",true)?;
                let helpers = book.open(Some(contents),"Helpers",true)?;
                let payload = book.open(Some(helpers),"MobileReleaseKitPayload.app",true)?;
                let code_chain = [outer,contents,helpers,payload];
                for original in code_chain {
                    book.protected_as(original,true,Some(0o555),AclRole::InputDirectory)?;
                    native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "producer-code-attributes")?;
                    book.check_name(original,true)?;
                }
                // Supplied copies/wrappers have a finite peak; this is not a
                // claim about Security.framework's private allocation heap.
                let supplied = ProducerVerifier::project_owned_upper_bound()
                    .and_then(|n| CurrentProductVerifier::project_owned_upper_bound().and_then(|m| m.checked_mul(2)?.checked_add(n)))
                    .and_then(|n| n.checked_add(2 * 65536 + 2 * 16384 + 4096))
                    .ok_or("producer-native-resource-bound")?;
                check(supplied <= 2 * 1024 * 1024,"producer-native-resource-bound")?;
                Ok(Self { input,signature:ProducerVerifier::new(),
                    entry:CurrentProductVerifier::new(CurrentProductRole::EntryApp),
                    payload:CurrentProductVerifier::new(CurrentProductRole::PayloadApp),code_chain,outer_path,
                    signature_result:None,entry_result:None,payload_result:None,descriptor:None,first:None })
            }
            fn inspect(&mut self, book: &Install, source: &Source) -> Result<ReleaseSetData> {
                use native::install_producer::{SignatureResult,CurrentProductResult};
                use mobile_release_desktop::{macos_install_producer::ProducerData,macos_install_maintenance::MaintenanceTargetData};
                check(self.signature_result.is_none() && self.entry_result.is_none()
                    && self.payload_result.is_none() && self.descriptor.is_none(),"producer-original-once")?;
                producer_original_post(book,source,&self.input,&self.code_chain)?;
                let signature = {
                    let Self { input,signature,code_chain,first,.. } = self;
                    signature.verify_and_close(input.descriptor_data(),input.signature_data(),
                        &mut |point| producer_point(book,source,input,code_chain,first,point))
                };
                self.signature_result = Some(signature);
                check(self.signature.settled(),"producer-native-finality-unknown")?;
                check(signature == SignatureResult::SignatureVerified,self.first.unwrap_or(match signature {
                    SignatureResult::Unavailable => "producer-source-unavailable",
                    SignatureResult::Unknown => "producer-native-custody-unknown",_ => "producer-signature-refused",
                }))?;
                // These remain parsed DATA until BOTH actual code roles have
                // matched and retired under this same original parent clock.
                let target = if cfg!(target_arch = "aarch64") { MaintenanceTargetData::Arm64 } else { MaintenanceTargetData::Intel };
                let descriptor = ProducerData::parse_data(self.input.descriptor_data(),target)
                    .map_err(|_| "producer-descriptor-binding")?;
                let signer = native::install_producer::source_signer_data().ok_or("producer-source-unavailable")?;
                producer_original_post(book,source,&self.input,&self.code_chain)?;
                check(producer_policy_matches_data(descriptor.signing_policy_data(),signer.team_data(),signer.leaf_sha1_data(),signer.leaf_sha256_data()),
                    "producer-current-policy-source")?;
                check(descriptor.completed_package_sha256_data() == self.input.package_sha256_data(),"producer-completed-package-binding")?;
                maintenance::selected_compile(descriptor.release_set_data())?;
                let entry = {
                    let Self { input,entry,code_chain,outer_path,first,.. } = self;
                    entry.verify_and_close(book.fd(code_chain[0])?.as_fd(),book.fd(code_chain[0])?.as_fd(),Path::new(outer_path),
                        &mut |point| producer_point(book,source,input,code_chain,first,point))
                };
                self.entry_result = Some(entry);
                check(self.entry.settled(),"producer-native-finality-unknown")?;
                check(entry == CurrentProductResult::PurposeVerified,self.first.unwrap_or(match entry {
                    CurrentProductResult::Unavailable => "producer-source-unavailable",
                    CurrentProductResult::Unknown => "producer-native-custody-unknown",_ => "producer-entry-purpose-refused",
                }))?;
                let payload = {
                    let Self { input,payload,code_chain,outer_path,first,.. } = self;
                    payload.verify_and_close(book.fd(code_chain[0])?.as_fd(),book.fd(code_chain[3])?.as_fd(),Path::new(outer_path),
                        &mut |point| producer_point(book,source,input,code_chain,first,point))
                };
                self.payload_result = Some(payload);
                check(self.payload.settled(),"producer-native-finality-unknown")?;
                check(payload == CurrentProductResult::PurposeVerified,self.first.unwrap_or(match payload {
                    CurrentProductResult::Unavailable => "producer-source-unavailable",
                    CurrentProductResult::Unknown => "producer-native-custody-unknown",_ => "producer-payload-purpose-refused",
                }))?;
                producer_original_post(book,source,&self.input,&self.code_chain)?;
                check(self.first.is_none(),"producer-original-refused")?;
                let selected = descriptor.release_set_data().clone();
                self.descriptor = Some(descriptor);
                Ok(selected)
            }
            fn authenticated_post(&self, book: &Install, source: &Source, content: bool) -> Result<()> {
                check(producer_results_data(self.signature_result,self.entry_result,self.payload_result,
                    self.descriptor.is_some(),self.first.is_none(),
                    [self.signature.settled(),self.entry.settled(),self.payload.settled()]),"producer-original-finality")?;
                producer_original_post(book,source,&self.input,&self.code_chain)?;
                if content { self.input.content_post(book)?; }
                Ok(())
            }
            fn settle(&mut self, book: &Install) -> bool {
                // Cleanup does not reinterpret changed source as authority. It
                // consumes only these original known CF references, inside the
                // same total120s; an unknown adapter refuses further native work.
                let mut gate = |point| producer_cleanup_point(book,point);
                let payload = self.payload.close(&mut gate);
                let entry = self.entry.close(&mut gate);
                let signature = self.signature.close(&mut gate);
                payload && entry && signature && self.payload.settled()
                    && self.entry.settled() && self.signature.settled()
            }
        }
        struct RemovalOriginals {
            input: completed_package::Input,
            // Native3 first fifteen originals, in its fixed documented order.
            code: [usize;15], installed_pair: [usize;2], installed_raw: [Vec<u8>;2],
        }
        impl RemovalOriginals {
            fn post(&self, book: &Install) -> Result<()> {
                self.input.post(book)?;
                for n in self.code { book.check_name(n,true)?; }
                for (n,raw) in self.installed_pair.iter().zip(&self.installed_raw) {
                    maintenance::held_bytes(book,*n,raw)?;
                }
                book.clock()
            }
        }
        fn removal_source_point(book: &Install, originals: &RemovalOriginals, first: &mut Option<&'static str>,
            point: native::install_producer::ProducerCheckpoint) -> native::android_service_management::Decision {
            use native::android_service_management::Decision;
            let (phase,custody)=producer_phase(point);
            if phase.is_cleanup() { return producer_cleanup_point(book,point); }
            if custody.unknown { first.get_or_insert("removal-native-custody-unknown"); return Decision::Unknown; }
            if first.is_some() { return Decision::Stop; }
            if let Err(error)=originals.post(book) {
                first.get_or_insert(error);
                return if book.shared_deadline().is_ok_and(Deadline::is_unknown) { Decision::Unknown } else { Decision::Stop };
            }
            Decision::Proceed
        }
        // Stored by the original Parent BEFORE any verifier call. Its raw
        // current data is not independently constructible writer authority.
        pub(super) struct RemovalAdmission {
            originals: RemovalOriginals,
            signature: native::install_producer::ProducerVerifier,
            entry: native::install_producer::CurrentProductVerifier,
            payload: native::install_producer::CurrentProductVerifier,
            remove: native::install_producer::RemovalProducerVerifier,
            program: native::install_producer::RemovalProgramVerifier,
            descriptor: Option<mobile_release_desktop::macos_install_producer::ProducerData>,
            removal: Option<mobile_release_desktop::macos_remove_producer::RemovalData>,
            inspected: bool, first: Option<&'static str>,
            code_sha256: Option<[[u8;32];3]>,
            existing_maintenance: Option<usize>,
        }
        impl RemovalAdmission {
            fn new(book: &mut Install, completed_path: &str) -> Result<Self> {
                use native::install_producer::{ProducerVerifier,CurrentProductVerifier,CurrentProductRole,
                    RemovalProducerVerifier,RemovalProgramVerifier};
                check(cfg!(feature="macos-installed-remover") && !cfg!(feature="macos-installed-installer-fixture")
                    && unistd::getuid().is_root() && unistd::geteuid().is_root()
                    && unistd::getgid().as_raw()==0 && unistd::getegid().as_raw()==0,"removal-fixed-role")?;
                native::platform().map_err(|_| "removal-platform")?;
                check(std::env::current_exe().ok().as_deref()==Some(Path::new(paths::REMOVER_BINARY)),"removal-fixed-image")?;
                check(book.removal_live_reserved==0 && book.removal_control_reserved==0
                    && !book.registration.entered && !book.gate.entered,"removal-original-once")?;
                let bound=ProducerVerifier::project_owned_upper_bound()
                    .and_then(|n| CurrentProductVerifier::project_owned_upper_bound()?.checked_mul(2)?.checked_add(n))
                    .and_then(|n| n.checked_add(RemovalProducerVerifier::project_owned_upper_bound()?))
                    .and_then(|n| n.checked_add(RemovalProgramVerifier::project_owned_upper_bound()?))
                    .and_then(|n| n.checked_add(native::removal_coordinator::RemovalPeer::project_owned_upper_bound()?))
                    // Retained raw pairs and their bounded parse/copy backing,
                    // plus current record. Inventory/history are charged by the
                    // SAME observe_admitted BudgetData, not a second allowance.
                    .and_then(|n| n.checked_add(6*65536+2*installation_record::RECORD_LIMIT))
                    .and_then(|n| n.checked_add(REMOVAL_REQUEST_RESERVE))
                    .ok_or("removal-control-bound")?;
                check(bound<=16*1024*1024,"removal-control-bound")?;
                book.removal_live_reserved=3;
                book.removal_control_reserved=bound as u64;
                let input=completed_package::Input::open_removal(book,completed_path)?;
                let mut code=[0usize;15];
                code[0]=book.open(None,"/",true)?;
                book.protected_as(code[0],true,None,AclRole::SystemRoot)?;
                for (slot,parent,name) in [(1,0,"Library"),(2,1,"Application Support"),(3,2,"MobileReleaseKit"),
                    (4,3,paths::APP_NAME),(5,4,"Contents"),(6,5,"Helpers"),(7,6,"MobileReleaseKitPayload.app"),
                    (8,7,"Contents"),(9,8,"MacOS"),(10,8,"Helpers"),(11,5,"MacOS"),
                    (12,11,"mrk-macos-entry"),(13,9,"mobile-release-kit-desktop"),(14,10,"mrk-macos-remove")] {
                    let directory=slot<12;
                    code[slot]=book.open(Some(code[parent]),name,directory)?;
                    let role=match slot {1=>AclRole::SystemLibrary,2=>AclRole::SystemSupport,_=>AclRole::Other};
                    book.protected_as(code[slot],directory,match slot {1|2=>None,3=>Some(0o755),_=>Some(0o555)},role)?;
                    native::no_xattrs(book.fd(code[slot])?.as_fd()).map_err(|_| "removal-current-attributes")?;
                    check(stat::fstat(book.fd(code[slot])?).map_err(|_| "removal-current-stat")?.st_flags==0,
                        "removal-current-flags")?;
                }
                let target=if cfg!(target_arch="aarch64") { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64 }
                    else { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Intel };
                let names=mobile_release_desktop::macos_install_producer::installed_control_names_data(target,paths::RELEASE)
                    .map_err(|_| "removal-current-control-name")?;
                let (descriptor,raw)=maintenance::metadata_original(book,code[3],&names.0,
                    mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT)?;
                let (signature,sign)=maintenance::metadata_original(book,code[3],&names.1,
                    mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT)?;
                let originals=RemovalOriginals { input,code,installed_pair:[descriptor,signature],installed_raw:[raw,sign] };
                originals.post(book)?;
                Ok(Self { originals,signature:ProducerVerifier::new(),entry:CurrentProductVerifier::new(CurrentProductRole::EntryApp),
                    payload:CurrentProductVerifier::new(CurrentProductRole::PayloadApp),remove:RemovalProducerVerifier::new(),
                    program:RemovalProgramVerifier::new(),descriptor:None,removal:None,inspected:false,first:None,code_sha256:None,existing_maintenance:None })
            }
            fn inspect(&mut self, book: &Install) -> Result<()> {
                use native::install_producer::{SignatureResult,CurrentProductResult,RemovalProgramResult};
                check(!self.inspected,"removal-original-once")?; self.inspected=true;
                self.originals.post(book)?;
                let removed={ let Self { originals,remove,first,.. }=self;
                    remove.verify_and_close(originals.input.descriptor_data(),originals.input.signature_data(),
                        &mut |point| removal_source_point(book,originals,first,point)) };
                check(removed==SignatureResult::SignatureVerified && self.remove.settled(),
                    self.first.unwrap_or("removal-package-signature"))?;
                let installed={ let Self { originals,signature,first,.. }=self;
                    signature.verify_and_close(&originals.installed_raw[0],&originals.installed_raw[1],
                        &mut |point| removal_source_point(book,originals,first,point)) };
                check(installed==SignatureResult::SignatureVerified && self.signature.settled(),
                    self.first.unwrap_or("removal-installed-signature"))?;
                let target=if cfg!(target_arch="aarch64") { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64 }
                    else { mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Intel };
                let removal=mobile_release_desktop::macos_remove_producer::RemovalData::parse_data(
                    self.originals.input.descriptor_data(),target).map_err(|_| "removal-package-descriptor")?;
                let descriptor=removal.installed_data(&self.originals.installed_raw[0]).map_err(|_| "removal-installed-binding")?;
                let binding=descriptor.release_set_data().current_data().binding_data();
                check(removal_source_binding_data(&binding,option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"),
                    option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),removal.binding_data().package_sha256,
                    self.originals.input.package_sha256_data()),"removal-source-binding")?;
                let signer=native::install_producer::source_signer_data().ok_or("removal-source-unavailable")?;
                check(producer_policy_matches_data(descriptor.signing_policy_data(),signer.team_data(),signer.leaf_sha1_data(),
                    signer.leaf_sha256_data()),"removal-source-policy")?;
                self.descriptor=Some(descriptor); self.removal=Some(removal);
                let entry={ let Self { originals,entry,first,.. }=self;
                    entry.verify_and_close(book.fd(originals.code[4])?.as_fd(),book.fd(originals.code[4])?.as_fd(),Path::new(paths::APP),
                        &mut |point| removal_source_point(book,originals,first,point)) };
                check(entry==CurrentProductResult::PurposeVerified && self.entry.settled(),self.first.unwrap_or("removal-entry-purpose"))?;
                let payload={ let Self { originals,payload,first,.. }=self;
                    payload.verify_and_close(book.fd(originals.code[4])?.as_fd(),book.fd(originals.code[7])?.as_fd(),Path::new(paths::APP),
                        &mut |point| removal_source_point(book,originals,first,point)) };
                check(payload==CurrentProductResult::PurposeVerified && self.payload.settled(),self.first.unwrap_or("removal-payload-purpose"))?;
                let program={ let Self { originals,program,first,.. }=self;
                    program.verify_and_close(book.fd(originals.code[10])?.as_fd(),book.fd(originals.code[14])?.as_fd(),Path::new(paths::PAYLOAD_HELPERS),
                        &mut |point| removal_source_point(book,originals,first,point)) };
                check(program==RemovalProgramResult::PurposeVerified && self.program.settled(),self.first.unwrap_or("removal-program-purpose"))?;
                self.current_selection(book).map(|_| ())
            }
            fn settled(&self) -> bool { self.signature.settled() && self.entry.settled() && self.payload.settled()
                && self.remove.settled() && self.program.settled() }
            fn settle(&mut self, book: &Install) -> bool {
                let mut gate=|point| producer_cleanup_point(book,point);
                let program=self.program.close(&mut gate); let payload=self.payload.close(&mut gate);
                let entry=self.entry.close(&mut gate); let signature=self.signature.close(&mut gate);
                let remove=self.remove.close(&mut gate);
                program && payload && entry && signature && remove && self.settled()
            }
            pub(super) fn root_original(&self) -> usize { self.originals.code[3] }
            pub(super) fn installed_bytes(&self) -> &[u8] { &self.originals.installed_raw[0] }
            pub(super) fn installed_signature_bytes(&self) -> &[u8] { &self.originals.installed_raw[1] }
            pub(super) fn current_selection(&self, book: &Install) -> Result<&ReleaseSetData> {
                check(removal_native_admitted_data(self.inspected,self.first.is_none(),
                    [self.signature.settled(),self.entry.settled(),self.payload.settled(),self.remove.settled(),self.program.settled()],
                    [self.signature.custody(),self.entry.custody(),self.payload.custody(),self.remove.custody(),self.program.custody()]),
                    "removal-native-admission")?;
                self.originals.post(book)?;
                self.descriptor.as_ref().map(|data|data.release_set_data()).ok_or("removal-current-descriptor")
            }
            fn reservation_held_post(&self, book: &Install) -> Result<()> {
                self.current_selection(book)?;
                check(!book.worker_stderr_is_gate && book.registration.entered
                    && book.registration.parent==Some(self.root_original()) && book.registration.verified
                    && book.registration.creation=="existing-not-modified" && book.registration.lock_attempted
                    && book.registration.exclusive_acquired && !book.registration.closed_under_maintenance,
                    "removal-original-reservation")?;
                book.registration_protected(book.registration.participant.ok_or("removal-original-reservation")?)
            }
            pub(super) fn reservation_post(&self, book: &Install) -> Result<()> {
                self.reservation_held_post(book)?;
                check(!book.gate.entered && !book.gate.lock_attempted && !book.gate.exclusive_acquired,
                    "removal-before-maintenance")
            }
            // Existing M is admitted while R remains held, BEFORE the first
            // full observation. No mkdir/create/repair/ordinary gate helper.
            fn admit_existing_maintenance(&mut self, book: &mut Install) -> Result<()> {
                self.reservation_post(book)?;
                check(self.existing_maintenance.is_none() && book.gate.participant.is_none()
                    && book.gate.parent.is_none() && book.gate.writer.is_none(), "removal-maintenance-once")?;
                book.gate.parent=Some(self.root_original());
                book.gate.creation="existing-not-modified";
                let reader=book.open_role(Some(self.root_original()),paths::MAINTENANCE_GATE_NAME,false,Role::GateParticipant)?;
                self.existing_maintenance=Some(reader); // Actual custody precedes fallible POST.
                book.gate_protected(reader)?;
                maintenance::held_bytes(book,reader,paths::MAINTENANCE_GATE_BYTES)?;
                book.gate.verified=true;
                self.existing_maintenance_post(book)?;
                self.reservation_post(book)
            }
            pub(super) fn existing_maintenance_post(&self, book: &Install) -> Result<()> {
                self.reservation_held_post(book)?;
                let reader=self.existing_maintenance.ok_or("removal-existing-maintenance")?;
                let original=book.originals.get(reader).ok_or("removal-existing-maintenance")?;
                check(book.gate.participant==Some(reader) && book.gate.parent==Some(self.root_original())
                    && book.gate.creation=="existing-not-modified" && book.gate.writer.is_none()
                    && book.gate.verified && original.state==State::Owned && original.role==Role::GateParticipant
                    && original.parent==Some(self.root_original()) && original.name==paths::MAINTENANCE_GATE_NAME,
                    "removal-existing-maintenance")?;
                check(fcntl::fcntl(book.fd(reader)?,fcntl::FcntlArg::F_GETFL).map_err(|_|"removal-maintenance-flags")?
                    & OFlag::O_ACCMODE.bits()==OFlag::O_RDONLY.bits(),"removal-maintenance-readonly")?;
                book.gate_protected(reader)?;
                maintenance::held_bytes(book,reader,paths::MAINTENANCE_GATE_BYTES)
            }
            pub(super) fn retained_source_index(&self,index:usize)->bool {
                self.originals.code.contains(&index) || self.originals.installed_pair.contains(&index)
                    || self.existing_maintenance==Some(index)
            }
            fn bind_inventory(&mut self, book: &Install, observed: &maintenance::RemovalObserved) -> Result<()> {
                check(self.code_sha256.is_none(),"removal-inventory-once")?;
                self.reservation_post(book)?; observed.post(book)?;
                let index=observed.inventory().index()?;
                let mut digests=[[0u8;32];3];
                for (slot,path) in [paths::ENTRY_INVENTORY_PATH,paths::PAYLOAD_INVENTORY_PATH,paths::REMOVER_INVENTORY_PATH].into_iter().enumerate() {
                    let entry=index.files.get(path).ok_or("removal-inventory-code")?;
                    check(entry.executable,"removal-inventory-code")?;
                    let digest=book.read(self.originals.code[12+slot],entry.size,false)?.0;
                    check(digest==entry.sha256,"removal-inventory-code")?;
                    for (n,byte) in digests[slot].iter_mut().enumerate() {
                        *byte=u8::from_str_radix(&digest[n*2..n*2+2],16).map_err(|_| "removal-inventory-code")?;
                    }
                }
                let removal=self.removal.as_ref().ok_or("removal-package-descriptor")?;
                check(index.files.get(paths::REMOVER_INVENTORY_PATH).is_some_and(|entry|
                    entry.sha256==removal.binding_data().remover_executable_sha256),"removal-package-code-binding")?;
                self.reservation_post(book)?; observed.post(book)?;
                self.code_sha256=Some(digests); Ok(())
            }
        }
        // Private non-Clone phase capability. PeerCompletion comes only from
        // the original native conversation/exit/retirement, not parsed DATA.
        pub(super) struct RemovalExclusion {
            peer: RemovalPeerCompletion, reservation: usize, maintenance: usize,
        }
        impl RemovalExclusion {
            pub(super) fn post(&self,book:&Install,source:&RemovalAdmission)->Result<()> {
                source.existing_maintenance_post(book)?;
                let retired=self.peer.retired();
                check(retired.role()==native::removal_coordinator::RemovalPeerRole::Parent
                    && retired.original_peer_exit_observed() && retired.peer_pid_data()>0
                    && book.registration.participant==Some(self.reservation)
                    && source.existing_maintenance==Some(self.maintenance)
                    && book.gate.entered && book.gate.lock_attempted && book.gate.exclusive_acquired,
                    "removal-exclusive-originals")?;
                // The unique private constructor below bound the exact request
                // before M; shared clock and current source remain live checks.
                book.clock()
            }
        }
        pub(super) fn removal_reobserve_budget_data(reserved:u64,retained_capacity:usize)->Result<u64> {
            check(retained_capacity>0 && retained_capacity<=transaction::STATE_LIMIT,"removal-state-overlap")?;
            reserved.checked_add(retained_capacity as u64).filter(|n|*n<=16*1024*1024)
                .ok_or("removal-control-bound")
        }
        // Held by the same Parent before publication. All fields come from
        // actual admitted originals and its one original deadline, never from
        // a renderer/argv-selected JSON tuple. Still no peer or file authority.
        struct RemovalRequest {
            data: mobile_release_desktop::macos_remove_protocol::RequestData,
            encoded: Vec<u8>, digest: [u8;32],
            native: native::removal_coordinator::RemovalChallengeData,
        }
        pub(super) fn removal_hex_data<const N:usize>(text:&str)->Result<[u8;N]> {
            check(text.len()==N*2 && text.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "removal-binding-hex")?;
            let mut value=[0;N];
            for (i,byte) in value.iter_mut().enumerate() {
                *byte=u8::from_str_radix(&text[2*i..2*i+2],16).map_err(|_| "removal-binding-hex")?;
            }
            check(value.iter().any(|b|*b!=0),"removal-binding-hex")?; Ok(value)
        }
        fn removal_native_binding_data(binding:&mobile_release_desktop::macos_remove_protocol::BindingData)
            ->Result<native::removal_coordinator::RemovalChallengeData> {
            use native::removal_coordinator::{RemovalChallengeData,RemovalTargetData};
            use mobile_release_desktop::macos_remove_protocol::TargetData;
            let fields=binding.fields_data();
            let mut release=[0;128];
            check(fields.release.len()<=release.len(),"removal-binding-release")?;
            release[..fields.release.len()].copy_from_slice(fields.release.as_bytes());
            let native=RemovalChallengeData {
                request_id:removal_hex_data(fields.request_id)?,root_nonce:removal_hex_data(fields.root_nonce)?,
                source:removal_hex_data(fields.source_commit)?,target:match fields.target {
                    TargetData::Arm64=>RemovalTargetData::Arm64,TargetData::Intel=>RemovalTargetData::Intel },
                release,release_len:u8::try_from(fields.release.len()).map_err(|_| "removal-binding-release")?,
                remove_producer:removal_hex_data(fields.remove_producer_sha256)?,
                installed_producer:removal_hex_data(fields.installed_producer_sha256)?,
                inventory:removal_hex_data(fields.installed_inventory_sha256)?,protocol:removal_hex_data(fields.protocol_sha256)?,
                start:fields.start,work:fields.work,hard:fields.hard,
            };
            check(native.valid_data(),"removal-native-binding")?; Ok(native)
        }
        impl RemovalRequest {
            fn new(book:&Install,source:&RemovalAdmission,observed:&maintenance::RemovalObserved)->Result<Self> {
                use mobile_release_desktop::macos_remove_protocol as protocol;
                source.reservation_post(book)?; observed.post(book)?;
                check(source.code_sha256.is_some(),"removal-inventory-missing")?;
                let selected=source.current_selection(book)?;
                let binding=selected.current_data().binding_data();
                let deadline=book.shared_deadline()?;
                let mut id=[0;16];let mut nonce=[0;16];
                book.clock()?;getrandom::fill(&mut id).map_err(|_| "removal-request-random")?;book.clock()?;
                getrandom::fill(&mut nonce).map_err(|_| "removal-request-random")?;book.clock()?;
                // A zero/duplicate/colliding value is a refusal, never a second
                // request identity, RNG retry loop or refreshed deadline.
                check(id!=[0;16] && nonce!=[0;16] && id!=nonce,"removal-request-random")?;
                let hex=|value:&[u8]|value.iter().map(|b|format!("{b:02x}")).collect::<String>();
                let id=hex(&id);let nonce=hex(&nonce);
                let remove_sha=format!("{:x}",Sha256::digest(source.originals.input.descriptor_data()));
                let installed_sha=format!("{:x}",Sha256::digest(source.installed_bytes()));
                let binding=protocol::BindingData::new_data(protocol::BindingInputData {
                    request_id:&id,root_nonce:&nonce,source_commit:binding.source_commit,release:binding.release,
                    target:if cfg!(target_arch="aarch64"){protocol::TargetData::Arm64}else{protocol::TargetData::Intel},
                    remove_producer_sha256:&remove_sha,installed_producer_sha256:&installed_sha,
                    installed_inventory_sha256:binding.inventory_sha256,protocol_sha256:binding.protocol_sha256,
                    start:deadline.start,work:deadline.end-SETTLEMENT,hard:deadline.end,
                }).map_err(|_| "removal-request-binding")?;
                let data=protocol::RequestData::new_data(&binding,source.originals.input.descriptor_data(),
                    source.originals.input.signature_data()).map_err(|_| "removal-request-data")?;
                let mut buffer=[0;protocol::REQUEST_LIMIT];
                let length=data.encode_data(&mut buffer).map_err(|_| "removal-request-data")?;
                let native=removal_native_binding_data(data.binding_data())?;
                let encoded=buffer[..length].to_vec();let digest=Sha256::digest(&encoded).into();
                let value=Self { data,encoded,digest,native };
                // Charge retained storage PLUS all temporary originals still
                // alive here, before permitting any successor publication.
                let bytes=value.retained_bytes()?.checked_add(buffer.len())
                    .and_then(|n|n.checked_add(binding.owned_bytes_data()?))
                    .and_then(|n|n.checked_add(id.capacity()+nonce.capacity()+remove_sha.capacity()+installed_sha.capacity()))
                    .ok_or("removal-request-bound")?;
                check(bytes<=REMOVAL_REQUEST_RESERVE,"removal-request-bound")?;
                source.reservation_post(book)?;observed.post(book)?;Ok(value)
            }
            fn retained_bytes(&self)->Result<usize> {
                self.data.owned_bytes_data().and_then(|n|n.checked_add(self.encoded.capacity()))
                    .and_then(|n|n.checked_add(std::mem::size_of::<Self>())).ok_or("removal-request-bound")
            }
            fn post(&self,book:&Install,source:&RemovalAdmission,observed:&maintenance::RemovalObserved)->Result<()> {
                source.reservation_post(book)?;observed.post(book)?;
                check(self.retained_bytes()?<=REMOVAL_REQUEST_RESERVE
                    && self.data.remove_descriptor_data()==source.originals.input.descriptor_data()
                    && self.data.remove_signature_data()==source.originals.input.signature_data()
                    && self.native==removal_native_binding_data(self.data.binding_data())?
                    && self.digest==<[u8;32]>::from(Sha256::digest(&self.encoded)),"removal-request-current")?;
                book.clock()
            }
        }
        const REMOVAL_REQUESTS_NAME:&str="MobileReleaseKit-RemovalRequests";
        // These fields record returned effects in the existing Parent/Book.
        // A complete JSON file is NOT native readiness or permission to quit.
        struct RemovalPublication {
            infrastructure:Option<usize>, directory:Option<usize>, writer:Option<usize>, reader:Option<usize>,
            attempted:bool, written:usize, sealed:bool, file_persisted:bool, directory_persisted:bool,
            writer_closed:bool, readback:bool,
        }
        fn removal_parent_change_data(before:Identity,before_flags:u32,actual:Identity,actual_flags:u32,
            named:Identity,named_flags:u32,created:bool)->bool {
            actual==named && actual_flags==named_flags && before_flags==actual_flags
                && before.dev==actual.dev && before.ino==actual.ino && before.mode==actual.mode
                && before.uid==actual.uid && before.gid==actual.gid
                && before.mode&0o170000==0o040000 && (created || before==actual)
        }
        fn removal_request_name_data(name:&str)->bool {
            name.len()==34 && name.starts_with("r-") && removal_hex_data::<16>(&name[2..]).is_ok()
        }
        impl RemovalPublication {
            fn new()->Self { Self { infrastructure:None,directory:None,writer:None,reader:None,attempted:false,
                written:0,sealed:false,file_persisted:false,directory_persisted:false,writer_closed:false,readback:false } }
            fn parent_before(book:&Install,n:usize)->Result<(Identity,u32)> {
                book.check_name(n,true)?;
                book.protected_as(n,true,None,if book.originals[n].name=="Application Support" {
                    AclRole::SystemSupport } else { AclRole::Other })?;
                book.clock()?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_| "removal-request-parent-stat")?;
                let original=&book.originals[n];
                let named=book.named(original.parent,&original.name).map_err(|_| "removal-request-parent-name")?;
                check(Identity::of(&actual)==book.identity(n)? && Identity::of(&actual)==Identity::of(&named)
                    && actual.st_flags==named.st_flags,"removal-request-parent-original")?;
                book.clock()?;Ok((Identity::of(&actual),actual.st_flags))
            }
            fn returned_parent_change(book:&mut Install,n:usize,before:(Identity,u32),created:bool)->Result<()> {
                book.clock()?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_| "removal-request-parent-stat")?;
                let original=&book.originals[n];
                let named=book.named(original.parent,&original.name).map_err(|_| "removal-request-parent-name")?;
                check(removal_parent_change_data(before.0,before.1,Identity::of(&actual),actual.st_flags,
                    Identity::of(&named),named.st_flags,created),"removal-request-parent-effect")?;
                book.protected_as(n,true,None,if book.originals[n].name=="Application Support" {
                    AclRole::SystemSupport } else { AclRole::Other })?;
                // Only this parent's returned own directory-entry effect can
                // advance its baseline. All other held originals stay exact.
                for (other,original) in book.originals.iter().enumerate() {
                    if other!=n && original.fd.is_some() { book.check_name(other,true)?; }
                }
                book.clock()?;
                book.originals[n].identity=Some(Identity::of(&actual));
                book.check_name(n,true)
            }
            fn directory(book:&mut Install,parent:usize,name:&str,fresh:bool)->Result<usize> {
                let before=Self::parent_before(book,parent)?;
                if fresh { book.absent(parent,name)?; }
                let effect=book.creations.len();
                let n=book.directory(parent,name,fresh,0o755)?;
                let returned=book.creations.get(effect).ok_or("removal-request-directory-effect")?;
                check(returned.parent==parent && returned.name==name && returned.identity==Some(book.identity(n)?)
                    && matches!(returned.state,"created"|"existing-not-modified")
                    && (!fresh || returned.state=="created"),"removal-request-directory-effect")?;
                let created=returned.state=="created";
                book.clock()?;
                check(stat::fstat(book.fd(n)?).map_err(|_| "removal-request-directory-stat")?.st_flags==0,
                    "removal-request-directory-flags")?;
                Self::returned_parent_change(book,parent,before,created)?; Ok(n)
            }
            // Only the fixed private request namespace is enumerated. Do not
            // expand the ordinary installer roster to accept sockets, or audit
            // unrelated entries in the user's Application Support directory.
            fn census(book:&Install,parent:usize,infrastructure:bool)->Result<BTreeSet<[u8;34]>> {
                book.check_name(parent,true)?;book.clock()?;
                check(unistd::lseek(book.fd(parent)?,0,unistd::Whence::SeekSet)
                    .map_err(|_| "removal-request-census-seek")?==0,"removal-request-census-seek")?;
                let mut found=BTreeSet::new();let mut block=[0u8;65536];
                loop {
                    book.clock()?;
                    let used=native::directory_block(book.fd(parent)?.as_fd(),&mut block)
                        .map_err(|_| "removal-request-census")?;
                    if used==0 { break; }
                    check(used<=block.len(),"removal-request-census-bound")?;
                    let mut offset=0;
                    while offset<used {
                        check(used-offset>=11,"removal-request-census-shape")?;
                        let kind=block[offset+8];
                        let inode=u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_| "removal-request-census-shape")?);
                        let length=usize::from(u16::from_ne_bytes([block[offset+9],block[offset+10]]));
                        let end=offset.checked_add(11+length).filter(|end|*end<=used).ok_or("removal-request-census-shape")?;
                        let name=std::str::from_utf8(&block[offset+11..end]).map_err(|_| "removal-request-census-name")?;
                        offset=end;
                        if name=="." || name==".." { continue; }
                        let valid=if infrastructure { kind==nix::libc::DT_DIR && removal_request_name_data(name) }
                            else { kind==nix::libc::DT_REG && name=="request.json" };
                        check(valid && inode!=0 && found.len()<if infrastructure {64}else{1},
                            "removal-request-census-bound")?;
                        let mut fixed=[0u8;34];fixed[..name.len()].copy_from_slice(name.as_bytes());
                        check(found.insert(fixed),"removal-request-census-duplicate")?;
                    }
                }
                book.check_name(parent,true)?;book.clock()?;Ok(found)
            }
            fn prepare(&mut self,book:&mut Install,source:&RemovalAdmission,observed:&maintenance::RemovalObserved,
                request:&RemovalRequest)->Result<()> {
                check(!self.attempted,"removal-request-publication-once")?;self.attempted=true;
                request.post(book,source,observed)?;
                // Includes the largest transient census block/two small sets,
                // readback block and this ledger in the already reserved256KiB.
                check(request.retained_bytes()?.checked_add(96*1024+std::mem::size_of::<Self>())
                    .is_some_and(|n|n<=REMOVAL_REQUEST_RESERVE),"removal-request-bound")?;
                let infrastructure=Self::directory(book,source.originals.code[2],REMOVAL_REQUESTS_NAME,false)?;
                self.infrastructure=Some(infrastructure);
                request.post(book,source,observed)?;
                let mut census=Self::census(book,infrastructure,true)?;
                check(census.len()<64,"removal-request-census-full")?;
                let name=format!("r-{}",request.data.binding_data().fields_data().request_id);
                check(removal_request_name_data(&name),"removal-request-directory-name")?;
                let directory=Self::directory(book,infrastructure,&name,true)?;
                self.directory=Some(directory);
                let fixed:[u8;34]=name.as_bytes().try_into().map_err(|_| "removal-request-directory-name")?;
                check(census.insert(fixed) && Self::census(book,infrastructure,true)?==census,"removal-request-census-changed")?;
                let before=Self::parent_before(book,directory)?;
                book.absent(directory,"request.json")?;
                let writer=book.create_file(directory,"request.json",Role::ReceiptWriter)?;
                self.writer=Some(writer);
                let file=book.identity(writer)?;
                check(file.mode==0o100600 && file.uid==0 && file.gid==0 && file.links==1 && file.size==0,
                    "removal-request-private-file")?;
                Self::returned_parent_change(book,directory,before,true)?;
                while self.written<request.encoded.len() {
                    book.clock()?;
                    let count=unistd::write(book.fd(writer)?,&request.encoded[self.written..])
                        .map_err(|_| "removal-request-write")?;
                    check(count>0 && count<=request.encoded.len()-self.written,"removal-request-write-bound")?;
                    self.written+=count;book.clock()?;
                }
                let actual=stat::fstat(book.fd(writer)?).map_err(|_| "removal-request-written-stat")?;
                let named=book.named(Some(directory),"request.json").map_err(|_| "removal-request-written-name")?;
                check(file.same_object(Identity::of(&actual)) && u32::from(actual.st_mode)==file.mode
                    && actual.st_nlink==1 && actual.st_size==self.written as i64 && actual.st_flags==0
                    && Identity::of(&actual)==Identity::of(&named) && named.st_flags==0,"removal-request-written-original")?;
                book.clock()?;
                stat::fchmod(book.fd(writer)?,Mode::from_bits_truncate(0o444)).map_err(|_| "removal-request-seal")?;
                self.sealed=true;book.clock()?;
                let sealed=stat::fstat(book.fd(writer)?).map_err(|_| "removal-request-sealed-stat")?;
                let named=book.named(Some(directory),"request.json").map_err(|_| "removal-request-sealed-name")?;
                check(file.same_object(Identity::of(&sealed)) && sealed.st_mode==0o100444 && sealed.st_nlink==1
                    && sealed.st_size==self.written as i64 && sealed.st_flags==0 && named.st_flags==0
                    && Identity::of(&sealed)==Identity::of(&named),"removal-request-sealed-original")?;
                book.originals[writer].identity=Some(Identity::of(&sealed));
                book.protected(writer,false,Some(0o444))?;
                native::no_xattrs(book.fd(writer)?.as_fd()).map_err(|_| "removal-request-file-attributes")?;
                book.clock()?;
                let persisted=native::sync(book.fd(writer)?.as_fd(),true);
                self.file_persisted=persisted.is_ok();persisted.map_err(|_| "removal-request-file-persist")?;book.clock()?;
                self.writer_closed=book.close(writer);check(self.writer_closed,"removal-request-writer-close")?;book.clock()?;
                let persisted=native::sync(book.fd(directory)?.as_fd(),false);
                self.directory_persisted=persisted.is_ok();persisted.map_err(|_| "removal-request-directory-persist")?;book.clock()?;
                let reader=book.open(Some(directory),"request.json",false)?;self.reader=Some(reader);
                check(book.identity(reader)?==Identity::of(&sealed),"removal-request-readback-original")?;
                book.protected(reader,false,Some(0o444))?;
                native::no_xattrs(book.fd(reader)?.as_fd()).map_err(|_| "removal-request-file-attributes")?;
                maintenance::held_bytes(book,reader,&request.encoded)?;
                self.readback=true;
                check(Self::census(book,directory,false)?.len()==1,"removal-request-file-roster")?;
                // The socket is absent until the same native peer owns its
                // returned bind/mode/listen effects. No ready hint is sent here.
                book.absent(directory,"s")?;book.check_name(directory,true)?;
                request.post(book,source,observed)
            }
        }
        fn removal_source_binding_data(binding:&mobile_release_desktop::macos_install_maintenance::ReleaseBindingData<'_>,
            source:Option<&str>,runtime:Option<&str>,package:&str,actual_package:&str) -> bool {
            binding.release==paths::RELEASE && binding.package_version==paths::PACKAGE_VERSION
                && binding.protocol_sha256==paths::PROTOCOL_SHA && Some(binding.source_commit)==source
                && Some(binding.runtime_manifest_sha256)==runtime && package==actual_package
        }
        fn removal_native_admitted_data(inspected:bool,first_absent:bool,settled:[bool;5],
            custody:[native::install_producer::ProducerCustody;5]) -> bool {
            use native::install_producer::{CurrentProductRole as Role,ProducerOperation as Operation};
            let roles=[Operation::DetachedSignature,Operation::CurrentProduct(Role::EntryApp),
                Operation::CurrentProduct(Role::PayloadApp),Operation::RemoveDetachedSignature,Operation::RemoveProgram];
            inspected && first_absent && settled==[true;5]
                && custody.iter().zip(roles).all(|(c,role)|c.operation==role && !c.failed && !c.unknown && !c.in_call && !c.gate_entered)
                && custody[0].signature_matched && custody[1].purpose_matched==Some(Role::EntryApp)
                && custody[2].purpose_matched==Some(Role::PayloadApp)
                && custody[3].remove_signature_matched && custody[4].remove_program_matched
        }
        fn producer_results_data(signature: Option<native::install_producer::SignatureResult>,
            entry: Option<native::install_producer::CurrentProductResult>,
            payload: Option<native::install_producer::CurrentProductResult>,
            descriptor: bool, no_original_refusal: bool, settled: [bool;3]) -> bool {
            use native::install_producer::{SignatureResult,CurrentProductResult};
            descriptor && no_original_refusal && settled.into_iter().all(|known| known)
                && signature == Some(SignatureResult::SignatureVerified)
                && entry == Some(CurrentProductResult::PurposeVerified)
                && payload == Some(CurrentProductResult::PurposeVerified)
        }
        fn completed_exit_data(writer_exit: Option<i32>, published: bool, exported: bool,
            originals: bool, native: bool, command_kernel_retained: bool, timely: bool,
            original_clean: bool, unknown: bool) -> i32 {
            if writer_exit == Some(0) && exported && originals && native && command_kernel_retained
                && timely && original_clean && !unknown { 0 }
            else if published || writer_exit == Some(20) { 20 }
            else { 1 }
        }
        use native::removal_coordinator as removal_peer_native;
        use mobile_release_desktop::macos_remove_protocol as removal_protocol;

        // Only this synchronous Parent scope borrows the original20. Nothing
        // here can create a verifier, R participant, app Completion or M lease.
        // The private returned native proof is not Clone/Serialize/Deserialize.
        struct RemovalPeerCompletion {
            retired: removal_peer_native::RemovalPeerRetired,
            preparation: removal_protocol::PreparationData,
            app_nonce: [u8;16],
        }
        impl RemovalPeerCompletion {
            fn retired(&self)->&removal_peer_native::RemovalPeerRetired { &self.retired }
            fn preparation_data(&self)->removal_protocol::PreparationData { self.preparation }
            fn app_nonce_data(&self)->[u8;16] { self.app_nonce }
        }

        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        enum RemovalPeerOwnPhase { Unbound, Binding, Bound, Mode, Published }
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        struct RemovalPeerOwnEffects {
            directory: removal_peer_native::RemovalOriginalData,
            socket: Option<removal_peer_native::RemovalOriginalData>,
            phase: RemovalPeerOwnPhase,
        }
        fn removal_peer_directory_data(value:removal_peer_native::RemovalOriginalData)->bool {
            value.inode!=0 && value.links!=0 && value.mode==0o40755
                && value.uid==0 && value.gid==0 && value.flags==0
                && value.modified_nanoseconds<1_000_000_000 && value.changed_nanoseconds<1_000_000_000
        }
        fn removal_peer_bind_data(before:removal_peer_native::RemovalOriginalData,
            after:removal_peer_native::RemovalOriginalData,socket:removal_peer_native::RemovalOriginalData)->bool {
            removal_peer_directory_data(before) && removal_peer_directory_data(after)
                && (before.device,before.inode,before.mode,before.uid,before.gid,before.flags)
                    ==(after.device,after.inode,after.mode,after.uid,after.gid,after.flags)
                && socket.device==after.device && socket.inode!=0 && socket.links==1
                && socket.mode&0o170000==0o140000 && socket.mode&0o7000==0
                && socket.uid==0 && socket.gid==0 && socket.flags==0
                && socket.modified_nanoseconds<1_000_000_000 && socket.changed_nanoseconds<1_000_000_000
        }
        fn removal_peer_mode_data(before:removal_peer_native::RemovalOriginalData,
            after:removal_peer_native::RemovalOriginalData)->bool {
            after.mode==0o140666 && after.modified_nanoseconds<1_000_000_000
                && after.changed_nanoseconds<1_000_000_000
                && after==(removal_peer_native::RemovalOriginalData {
                    mode:0o140666,changed_seconds:after.changed_seconds,
                    changed_nanoseconds:after.changed_nanoseconds,..before })
        }
        impl RemovalPeerOwnEffects {
            fn new_data(directory:removal_peer_native::RemovalOriginalData)->Result<Self> {
                check(removal_peer_directory_data(directory),"removal-peer-directory-shape")?;
                Ok(Self { directory,socket:None,phase:RemovalPeerOwnPhase::Unbound })
            }
            // Only the actual typed callbacks call this reducer. Returned facts
            // are recorded before a later clock veto, but are NOT committed to
            // Book or accepted as current until full held/named POST succeeds.
            fn transition_data(&mut self,phase:removal_peer_native::RemovalNativePhase,slot:Option<u8>,before:bool,
                directory:removal_peer_native::RemovalOriginalData,socket:removal_peer_native::RemovalOriginalData)->Result<()> {
                use removal_peer_native::RemovalNativePhase::{Bind,SocketMode};
                check(slot==Some(0),"removal-peer-own-slot")?;
                match (phase,before,self.phase) {
                    (Bind,true,RemovalPeerOwnPhase::Unbound) => {
                        check(directory==self.directory && socket==removal_peer_native::RemovalOriginalData::default(),
                            "removal-peer-bind-before")?;
                        self.phase=RemovalPeerOwnPhase::Binding;
                    },
                    (Bind,false,RemovalPeerOwnPhase::Binding) => {
                        check(self.socket.is_none() && removal_peer_bind_data(self.directory,directory,socket),
                            "removal-peer-bind-return")?;
                        self.directory=directory;self.socket=Some(socket);self.phase=RemovalPeerOwnPhase::Bound;
                    },
                    (SocketMode,true,RemovalPeerOwnPhase::Bound) => {
                        check(directory==self.directory && self.socket==Some(socket),"removal-peer-mode-before")?;
                        self.phase=RemovalPeerOwnPhase::Mode;
                    },
                    (SocketMode,false,RemovalPeerOwnPhase::Mode) => {
                        check(directory==self.directory && self.socket.is_some_and(|old|removal_peer_mode_data(old,socket)),
                            "removal-peer-mode-return")?;
                        self.socket=Some(socket);self.phase=RemovalPeerOwnPhase::Published;
                    },
                    _=>return Err("removal-peer-own-sequence"),
                }
                Ok(())
            }
        }
        fn removal_peer_stat_data(value:&FileStat)->Result<removal_peer_native::RemovalOriginalData> {
            check(value.st_size>=0 && (0..1_000_000_000).contains(&value.st_mtime_nsec)
                && (0..1_000_000_000).contains(&value.st_ctime_nsec),"removal-peer-stat-shape")?;
            Ok(removal_peer_native::RemovalOriginalData { device:value.st_dev as u64,inode:value.st_ino,
                links:u64::from(value.st_nlink),size:value.st_size as u64,
                modified_seconds:value.st_mtime,changed_seconds:value.st_ctime,
                mode:u32::from(value.st_mode),uid:value.st_uid,gid:value.st_gid,flags:value.st_flags,
                modified_nanoseconds:value.st_mtime_nsec as u32,changed_nanoseconds:value.st_ctime_nsec as u32 })
        }
        fn removal_peer_cleanup_data(phase:removal_peer_native::RemovalPeerPhase)->bool {
            use removal_peer_native::{RemovalPeerPhase as Phase,RemovalPeerOperation as Operation};
            matches!(phase,Phase::Call(Operation::WaitExit|Operation::Close)|Phase::Native{cleanup:true,..}|Phase::Retire)
        }
        fn removal_peer_begin_data(index:u32,custody:removal_peer_native::RemovalPeerCustody)->bool {
            custody.role==removal_peer_native::RemovalPeerRole::Parent && index<4
                && custody.frame_index==index && custody.frame_pending && custody.frames_bytes==0
                && !custody.failed && !custody.unknown && !custody.native_closed
        }
        fn removal_peer_complete_data(index:u32,custody:removal_peer_native::RemovalPeerCustody)->bool {
            custody.role==removal_peer_native::RemovalPeerRole::Parent && index<4
                && custody.frame_index==index+1 && !custody.frame_pending
                && (5..=removal_protocol::FRAME_LIMIT as u32).contains(&custody.frames_bytes)
        }
        fn removal_peer_known_retired_data(settled:bool,custody:removal_peer_native::RemovalPeerCustody)->bool {
            use native::android_service_management::CellCustody;
            // Known absence/consumption only, deliberately not a success test.
            settled && !custody.in_call && !custody.in_gate
                && matches!(custody.cell,CellCustody::Absent|CellCustody::Consumed)
                && custody.fds.iter().chain(&custody.references).all(|state|matches!(*state,0|4))
        }
        fn removal_peer_roster_entry_data(seen:u8,inode:u64,kind:u8,name:&[u8],request_inode:u64,
            socket:Option<removal_peer_native::RemovalOriginalData>)->Result<u8> {
            check(seen<=3 && inode!=0,"removal-peer-census-shape")?;
            let bit=match name {
                b"request.json" if kind==nix::libc::DT_REG && inode==request_inode =>1,
                b"s" if kind==nix::libc::DT_SOCK && socket.is_some_and(|socket|socket.inode==inode) =>2,
                _=>return Err("removal-peer-census-entry"),
            };
            check(seen&bit==0,"removal-peer-census-duplicate")?;Ok(seen|bit)
        }
        struct RemovalPeerLocal {
            effects:RemovalPeerOwnEffects,
            first:Option<&'static str>, native_first:Option<(u32,u64)>,
            last:Option<removal_peer_native::RemovalPeerCustody>,
            hint_attempted:bool,ack_complete:bool,exit_started:bool,
        }
        impl RemovalPeerLocal {
            fn new(effects:RemovalPeerOwnEffects)->Self { Self { effects,first:None,native_first:None,last:None,
                hint_attempted:false,ack_complete:false,exit_started:false } }
            fn note(&mut self,error:&'static str) { self.first.get_or_insert(error); }
            fn observe(&mut self,custody:removal_peer_native::RemovalPeerCustody) {
                // Preserve the actual native first code/raw sample BEFORE a
                // subsequent Parent clock/source/formatting refusal. Do not
                // turn an Instant into historical MONOTONIC provenance.
                if custody.native_first_code!=0 {
                    let returned=(custody.native_first_code,custody.native_first_failure);
                    if self.native_first.is_some_and(|old|old!=returned) { self.note("removal-peer-first-drift"); }
                    self.native_first.get_or_insert(returned);
                }
                if custody.unknown { self.note("removal-peer-native-unknown"); }
                else if custody.failed { self.note("removal-peer-native-refused"); }
                if custody.role!=removal_peer_native::RemovalPeerRole::Parent { self.note("removal-peer-role"); }
                // Latch actual final bytes even when the enclosing POST has
                // just failed. No intervening Recheck/Copy/Close may query a
                // departed guest before the SAME original WaitExit operation.
                if removal_peer_complete_data(3,custody) { self.ack_complete=true; }
                self.last=Some(custody);
            }
            fn before_call_data(&mut self,operation:removal_peer_native::RemovalPeerOperation)->Result<()> {
                use removal_peer_native::RemovalPeerOperation as Operation;
                check(!self.ack_complete || operation==Operation::WaitExit
                    || self.exit_started && operation==Operation::Close,"removal-peer-ack-next-exit")?;
                if operation==Operation::WaitExit {
                    check(self.ack_complete,"removal-peer-exit-before-ack")?;
                    self.exit_started=true;
                }
                Ok(())
            }
        }
        struct RemovalPeerContext<'a> {
            book:&'a Install,source:&'a RemovalAdmission,observed:&'a maintenance::RemovalObserved,
            request:&'a RemovalRequest,publication:&'a RemovalPublication,
            originals:[usize;20],directory:usize,reader:usize,
        }
        impl<'a> RemovalPeerContext<'a> {
            fn new(book:&'a Install,source:&'a RemovalAdmission,observed:&'a maintenance::RemovalObserved,
                request:&'a RemovalRequest,publication:&'a RemovalPublication)->Result<(Self,RemovalPeerOwnEffects)> {
                request.post(book,source,observed)?;
                check(publication.attempted && publication.sealed && publication.file_persisted
                    && publication.directory_persisted && publication.writer_closed && publication.readback
                    && publication.written==request.encoded.len(),"removal-peer-publication-original")?;
                let infrastructure=publication.infrastructure.ok_or("removal-peer-infrastructure")?;
                let directory=publication.directory.ok_or("removal-peer-directory")?;
                let reader=publication.reader.ok_or("removal-peer-reader")?;
                let writer=publication.writer.ok_or("removal-peer-writer")?;
                check(book.originals.get(writer).is_some_and(|original|original.fd.is_none() && original.state==State::Closed),
                    "removal-peer-writer-not-closed")?;
                check(book.originals[directory].parent==Some(infrastructure)
                    && book.originals[directory].name.len()==34
                    && book.originals[directory].name.strip_prefix("r-")==Some(request.data.binding_data().fields_data().request_id)
                    && book.originals[infrastructure].parent==Some(source.originals.code[2])
                    && book.originals[infrastructure].name==REMOVAL_REQUESTS_NAME
                    && book.originals[reader].parent==Some(directory) && book.originals[reader].name=="request.json",
                    "removal-peer-fixed-namespace")?;
                let mut originals=[0usize;20];originals[..15].copy_from_slice(&source.originals.code);
                originals[15..17].copy_from_slice(&source.originals.installed_pair);
                originals[17]=infrastructure;originals[18]=directory;originals[19]=reader;
                check(originals.iter().enumerate().all(|(i,n)|!originals[..i].contains(n)),"removal-peer-original-slots")?;
                let actual=stat::fstat(book.fd(directory)?).map_err(|_|"removal-peer-directory-stat")?;
                check(Identity::of(&actual)==book.identity(directory)?,"removal-peer-directory-before")?;
                let effects=RemovalPeerOwnEffects::new_data(removal_peer_stat_data(&actual)?)?;
                let context=Self {book,source,observed,request,publication,originals,directory,reader};
                context.post(&effects)?;context.storage(None,None)?;
                Ok((context,effects))
            }
            fn borrowed(&self)->Result<[BorrowedFd<'a>;20]> {
                // Array of borrows, not duplicated OFDs or a second ledger.
                let mut values=[self.book.fd(self.originals[0])?.as_fd();20];
                for (slot,n) in self.originals.iter().enumerate() { values[slot]=self.book.fd(*n)?.as_fd(); }
                Ok(values)
            }
            fn native_originals(&self)->Result<removal_peer_native::RemovalSourceOriginals<'a>> {
                removal_peer_native::RemovalSourceOriginals::new(&self.source.signature,&self.source.entry,&self.source.payload,
                    &self.source.remove,Some(&self.source.program),self.borrowed()?,
                    [&self.source.originals.installed_raw[0],&self.source.originals.installed_raw[1],
                        self.source.originals.input.descriptor_data(),self.source.originals.input.signature_data()],
                    self.source.code_sha256.ok_or("removal-peer-code-binding")?,self.request.digest)
                    .ok_or("removal-peer-verifier-originals")
            }
            fn storage(&self,transcript:Option<&removal_protocol::TranscriptData>,frame:Option<&removal_protocol::FrameData>)->Result<()> {
                // Same precharged256KiB sub-reservation of the Parent16MiB.
                // 96KiB includes the 64KiB closed-directory block, bounded
                // 4KiB-frame serde/copy temporaries and ordinary positional
                // source-read stack overlap. Native supplied storage is already
                // charged by RemovalAdmission::new, not a second allowance.
                let transcript=transcript.map_or(Some(0),|value|value.owned_bytes_data()).ok_or("removal-peer-storage")?;
                let frame=frame.map_or(Some(0),|value|value.owned_bytes_data()).ok_or("removal-peer-storage")?;
                let total=self.request.retained_bytes()?.checked_add(96*1024)
                    .and_then(|n|n.checked_add(removal_protocol::FRAME_LIMIT))
                    .and_then(|n|n.checked_add(std::mem::size_of::<Self>()+std::mem::size_of::<RemovalPublication>()
                        +2*std::mem::size_of::<RemovalPeerLocal>()+std::mem::size_of::<RemovalPeerScope>()
                        +std::mem::size_of::<RemovalPeerCompletion>()+20*std::mem::size_of::<BorrowedFd<'_>>()))
                    .and_then(|n|n.checked_add(transcript)).and_then(|n|n.checked_add(frame)).ok_or("removal-peer-storage")?;
                check(total<=REMOVAL_REQUEST_RESERVE && self.book.removal_live_reserved==3
                    && self.book.removal_control_reserved<=16*1024*1024
                    && self.book.removal_control_reserved>=REMOVAL_REQUEST_RESERVE as u64,"removal-peer-storage")
            }
            fn directory_post(&self,effects:&RemovalPeerOwnEffects)->Result<Identity> {
                let actual=stat::fstat(self.book.fd(self.directory)?).map_err(|_|"removal-peer-directory-stat")?;
                let original=&self.book.originals[self.directory];
                let named=self.book.named(original.parent,&original.name).map_err(|_|"removal-peer-directory-name")?;
                check(removal_peer_stat_data(&actual)?==effects.directory && removal_peer_stat_data(&named)?==effects.directory,
                    "removal-peer-directory-post")?;
                self.book.protected(self.directory,true,Some(0o755))?;
                native::no_xattrs(self.book.fd(self.directory)?.as_fd()).map_err(|_|"removal-peer-directory-attributes")?;
                self.book.clock()?;Ok(Identity::of(&actual))
            }
            fn census(&self,effects:&RemovalPeerOwnEffects)->Result<()> {
                self.book.clock()?;self.directory_post(effects)?;
                check(unistd::lseek(self.book.fd(self.directory)?,0,unistd::Whence::SeekSet)
                    .map_err(|_|"removal-peer-census-seek")?==0,"removal-peer-census-seek")?;
                let mut block=[0u8;65536];let mut seen=0u8;
                loop {
                    self.book.clock()?;
                    let used=native::directory_block(self.book.fd(self.directory)?.as_fd(),&mut block)
                        .map_err(|_|"removal-peer-census-read")?;
                    if used==0 { break; }
                    check(used<=block.len(),"removal-peer-census-bound")?;
                    let mut offset=0;
                    while offset<used {
                        check(used-offset>=11,"removal-peer-census-shape")?;
                        let inode=u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_|"removal-peer-census-shape")?);
                        let kind=block[offset+8];let length=usize::from(u16::from_ne_bytes([block[offset+9],block[offset+10]]));
                        let end=offset.checked_add(11+length).filter(|end|*end<=used).ok_or("removal-peer-census-shape")?;
                        let name=&block[offset+11..end];offset=end;
                        if name==b"." || name==b".." { continue; }
                        seen=removal_peer_roster_entry_data(seen,inode,kind,name,self.book.identity(self.reader)?.ino,effects.socket)?;
                    }
                }
                check(seen==if effects.socket.is_some(){3}else{1},"removal-peer-census-roster")?;
                self.directory_post(effects)?;self.book.clock()
            }
            fn post(&self,effects:&RemovalPeerOwnEffects)->Result<()> {
                self.request.post(self.book,self.source,self.observed)?;
                // No global relaxed-name policy. Exactly the requestdir's
                // original own-effect baseline is local while native borrows
                // Book; every other still-owned original stays full-exact.
                for (n,original) in self.book.originals.iter().enumerate() {
                    if original.fd.is_some() && n!=self.directory { self.book.check_name(n,true)?; }
                }
                self.directory_post(effects)?;
                let named=stat::fstatat(self.book.fd(self.directory)?,"s",AtFlags::AT_SYMLINK_NOFOLLOW);
                match (effects.socket,named) {
                    (None,Err(Errno::ENOENT))=>(),
                    (Some(expected),Ok(actual))=>check(removal_peer_stat_data(&actual)?==expected,"removal-peer-socket-post")?,
                    _=>return Err("removal-peer-socket-post"),
                }
                maintenance::held_bytes(self.book,self.reader,&self.request.encoded)?;
                self.census(effects)?;self.book.clock()
            }
            fn checkpoint(&self,local:&std::cell::RefCell<RemovalPeerLocal>,point:removal_peer_native::RemovalPeerCheckpoint)
                ->native::android_service_management::Decision {
                use native::android_service_management::Decision;
                use removal_peer_native::{RemovalPeerCheckpoint as Point,RemovalPeerPhase as Phase,RemovalNativePhase as NativePhase};
                let (phase,before,custody)=match point {
                    Point::Before{phase,custody}=>(phase,true,custody),
                    Point::Returned{phase,custody,..}=>(phase,false,custody),
                };
                let Ok(mut ledger)=local.try_borrow_mut() else { return Decision::Unknown; };
                ledger.observe(custody);
                if let Phase::Native{phase:own @ (NativePhase::Bind|NativePhase::SocketMode),slot,..}=phase {
                    if let Err(error)=ledger.effects.transition_data(own,slot,before,custody.request_directory,custody.socket_name) {
                        ledger.note(error);
                    }
                }
                let cleanup=removal_peer_cleanup_data(phase);let effects=ledger.effects;let first=ledger.first;
                drop(ledger);
                // Known consuming cleanup is permitted under the SAME hard
                // endpoint after a positive failure, not under a new budget.
                // It never clears first failure or turns None into a proof.
                let result=if cleanup { self.book.shared_deadline().and_then(Deadline::check_total).map(|_|()) }
                    else if let Some(error)=first { Err(error) } else { self.post(&effects) };
                if let Err(error)=result {
                    if let Ok(mut ledger)=local.try_borrow_mut() { ledger.note(error); }
                    return if self.book.shared_deadline().is_ok_and(Deadline::is_unknown) { Decision::Unknown } else { Decision::Stop };
                }
                Decision::Proceed
            }
        }
        struct RemovalPeerScope {
            proof:Option<removal_peer_native::RemovalPeerRetired>,
            preparation:Option<removal_protocol::PreparationData>,app_nonce:Option<[u8;16]>,
            effects:RemovalPeerOwnEffects,first:Option<&'static str>,native_first:Option<(u32,u64)>,
            custody:Option<removal_peer_native::RemovalPeerCustody>,settled:bool,
        }
        impl RemovalPeerScope {
            fn into_completion(self,expected:&removal_peer_native::RemovalChallengeData)
                ->Result<(RemovalPeerCompletion,RemovalPeerOwnEffects)> {
                if let Some(error)=self.first { return Err(error); }
                check(self.settled,"removal-peer-not-retired")?;
                // This must be the actual nonClone return, not a bool built
                // from EOF, transcript state, known absence or copied stats.
                let retired=self.proof.ok_or("removal-peer-success-proof-missing")?;
                let custody=self.custody.ok_or("removal-peer-custody-missing")?;
                check(retired.role()==removal_peer_native::RemovalPeerRole::Parent
                    && retired.binding_data()==expected && retired.original_peer_exit_observed()
                    && retired.peer_pid_data()>1 && retired.peer_pid_data()==custody.peer_pid
                    && !custody.failed && !custody.unknown && custody.native_closed && custody.actual_exit_observed
                    && custody.cell==native::android_service_management::CellCustody::Consumed
                    && custody.native_calls==custody.native_returns && removal_peer_complete_data(3,custody)
                    && removal_peer_known_retired_data(true,custody),"removal-peer-private-proof-current")?;
                let preparation=self.preparation.ok_or("removal-peer-preparation-missing")?;
                let app_nonce=self.app_nonce.ok_or("removal-peer-nonce-missing")?;
                check(app_nonce!=[0;16] && app_nonce!=expected.request_id && app_nonce!=expected.root_nonce
                    && self.effects.phase==RemovalPeerOwnPhase::Published,"removal-peer-transcript-current")?;
                Ok((RemovalPeerCompletion {retired,preparation,app_nonce},self.effects))
            }
        }
        fn removal_peer_returned(local:&std::cell::RefCell<RemovalPeerLocal>,peer:&removal_peer_native::RemovalPeer<'_>,
            progress:removal_peer_native::RemovalPeerProgress)->Result<removal_peer_native::RemovalPeerCustody> {
            let custody=peer.custody();let mut ledger=local.borrow_mut();ledger.observe(custody);
            if matches!(progress,removal_peer_native::RemovalPeerProgress::Refused|removal_peer_native::RemovalPeerProgress::Unknown) {
                ledger.note("removal-peer-original-return");
            }
            match ledger.first {Some(error)=>Err(error),None=>Ok(custody)}
        }
        fn removal_peer_pending_wait(context:&RemovalPeerContext<'_>,local:&std::cell::RefCell<RemovalPeerLocal>,work:bool)->Result<()> {
            let deadline=context.book.shared_deadline()?;
            let timeout=deadline.poll_ms(work)?;
            // Existing bounded poll primitive, no extra descriptor, worker,
            // channel, timeout epoch or retry of a failed native acquisition.
            match poll(&mut [],timeout) { Ok(0)|Err(Errno::EINTR)=>(),_=>return Err("removal-peer-pending-poll") }
            if work { context.post(&local.borrow().effects)?; } else { deadline.check_total()?; }
            Ok(())
        }
        fn removal_peer_poll_frame(context:&RemovalPeerContext<'_>,local:&std::cell::RefCell<RemovalPeerLocal>,
            peer:&mut removal_peer_native::RemovalPeer<'_>,index:u32,
            gate:&mut dyn FnMut(removal_peer_native::RemovalPeerCheckpoint)->native::android_service_management::Decision)
            ->Result<removal_peer_native::RemovalPeerCustody> {
            use removal_peer_native::{RemovalPeerOperation as Operation,RemovalPeerProgress as Progress};
            loop {
                local.borrow_mut().before_call_data(Operation::PollFrame)?;
                let progress=peer.poll_frame(gate);
                // Record actual final Ack bytes even if a following POST
                // refuses. Caller must next attempt the SAME original WaitExit.
                let custody=removal_peer_returned(local,peer,progress)?;
                if progress==Progress::Ready {
                    check(removal_peer_complete_data(index,custody),"removal-peer-frame-completion")?;
                    return Ok(custody);
                }
                check(progress==Progress::Pending && custody.frame_index==index && custody.frame_pending,
                    "removal-peer-frame-pending")?;
                removal_peer_pending_wait(context,local,true)?;
            }
        }
        fn removal_peer_transcript(context:&RemovalPeerContext<'_>,local:&std::cell::RefCell<RemovalPeerLocal>,
            transcript:&mut removal_protocol::TranscriptData,action:removal_protocol::ActionData,bytes:&[u8])->Result<()> {
            context.storage(Some(transcript),None)?;context.post(&local.borrow().effects)?;
            let now=context.book.shared_deadline()?.check_work()?;
            // Only the actual completed bytes cross the one existing closed
            // parser. No DTO or acknowledged intent stands in for this read.
            let frame=transcript.advance_data(action,bytes,now).map_err(|_|"removal-peer-transcript")?;
            context.storage(Some(transcript),Some(&frame))?;
            drop(frame);context.post(&local.borrow().effects)
        }
        fn removal_peer_forward(context:&RemovalPeerContext<'_>,local:&std::cell::RefCell<RemovalPeerLocal>,
            peer:&mut removal_peer_native::RemovalPeer<'_>,transcript:&mut removal_protocol::TranscriptData,
            buffer:&mut [u8;removal_protocol::FRAME_LIMIT],ready_hint:fn(&str)->Result<()>,
            gate:&mut dyn FnMut(removal_peer_native::RemovalPeerCheckpoint)->native::android_service_management::Decision)
            ->Result<(removal_protocol::PreparationData,[u8;16])> {
            use removal_peer_native::{RemovalPeerOperation as Operation,RemovalPeerProgress as Progress};
            use removal_protocol::{ActionData,FrameData,ProgressData};
            if let Some(error)=local.borrow().first { return Err(error); }
            local.borrow_mut().before_call_data(Operation::Source)?;
            let progress=peer.admit_source(gate);let custody=removal_peer_returned(local,peer,progress)?;
            check(progress==Progress::Ready && custody.native_stage==1,"removal-peer-source-ready")?;
            local.borrow_mut().before_call_data(Operation::Open)?;
            let progress=peer.open(gate);let custody=removal_peer_returned(local,peer,progress)?;
            check(progress==Progress::Ready && custody.native_stage==2
                && local.borrow().effects.phase==RemovalPeerOwnPhase::Published,"removal-peer-open-ready")?;
            context.post(&local.borrow().effects)?;
            {
                let mut ledger=local.borrow_mut();check(!ledger.hint_attempted,"removal-peer-hint-once")?;
                ledger.hint_attempted=true;
            }
            // Fixed SOURCE-selected delivery only. There is deliberately no
            // noop/default or entry caller. A successful post is not discovery,
            // authentication, app consent or permission to skip the next steps.
            ready_hint(context.request.data.binding_data().fields_data().request_id)?;
            context.post(&local.borrow().effects)?;
            loop {
                local.borrow_mut().before_call_data(Operation::Connect)?;
                let progress=peer.connect(gate);let custody=removal_peer_returned(local,peer,progress)?;
                if progress==Progress::Ready {
                    check(custody.native_stage==3,"removal-peer-connected-stage")?;break;
                }
                check(progress==Progress::Pending && custody.native_stage==2,"removal-peer-connect-pending")?;
                removal_peer_pending_wait(context,local,true)?;
            }
            local.borrow_mut().before_call_data(Operation::Authenticate)?;
            let progress=peer.authenticate(gate);let custody=removal_peer_returned(local,peer,progress)?;
            check(progress==Progress::Ready && custody.native_stage==4 && custody.peer_pid>1 && custody.peer_uid!=0
                && custody.frame_index==0 && !custody.frame_pending,"removal-peer-authenticated-original")?;

            let challenge=FrameData::challenge_data(context.request.data.binding_data()).map_err(|_|"removal-peer-challenge")?;
            context.storage(Some(transcript),Some(&challenge))?;
            let used=challenge.encode_framed_data(buffer).map_err(|_|"removal-peer-frame-encode")?;
            drop(challenge);context.post(&local.borrow().effects)?;
            local.borrow_mut().before_call_data(Operation::BeginFrame)?;
            let progress=peer.send_challenge(&buffer[..used],gate);let custody=removal_peer_returned(local,peer,progress)?;
            check(progress==Progress::Ready && removal_peer_begin_data(0,custody),"removal-peer-challenge-begin")?;
            let custody=removal_peer_poll_frame(context,local,peer,0,gate)?;
            check(custody.frames_bytes as usize==used,"removal-peer-challenge-returned-bytes")?;
            removal_peer_transcript(context,local,transcript,ActionData::Send,&buffer[..used])?;
            buffer.fill(0);

            for index in [1u32,2u32] {
                context.post(&local.borrow().effects)?;
                local.borrow_mut().before_call_data(Operation::BeginFrame)?;
                let progress=peer.receive(gate);let custody=removal_peer_returned(local,peer,progress)?;
                check(progress==Progress::Ready && removal_peer_begin_data(index,custody),"removal-peer-receive-begin")?;
                removal_peer_poll_frame(context,local,peer,index,gate)?;
                // Native copy consumes exactly once and independently checks
                // current same-peer/code/watch. These are Confirmed/Prepared,
                // not the terminal Ack; no copy is attempted after Ack send.
                let received=peer.received_frame(gate).map_err(|_|"removal-peer-received-original")?;
                removal_peer_transcript(context,local,transcript,ActionData::Receive,received)?;
                local.borrow_mut().observe(peer.custody());
            }
            check(transcript.progress_data()==ProgressData::AwaitQuitAcknowledged && transcript.first_error_data().is_none(),
                "removal-peer-prepared-transcript")?;
            let preparation=transcript.preparation_data().ok_or("removal-peer-prepared-branch")?;
            let nonce=removal_hex_data::<16>(transcript.app_nonce_data().ok_or("removal-peer-app-nonce")?)?;
            let ack=FrameData::quit_acknowledged_data(context.request.data.binding_data(),
                transcript.app_nonce_data().ok_or("removal-peer-app-nonce")?).map_err(|_|"removal-peer-ack")?;
            context.storage(Some(transcript),Some(&ack))?;
            let used=ack.encode_framed_data(buffer).map_err(|_|"removal-peer-frame-encode")?;
            drop(ack);context.post(&local.borrow().effects)?;
            local.borrow_mut().before_call_data(Operation::BeginFrame)?;
            let progress=peer.send_quit_acknowledged(&buffer[..used],gate);let custody=removal_peer_returned(local,peer,progress)?;
            check(progress==Progress::Ready && removal_peer_begin_data(3,custody),"removal-peer-ack-begin")?;
            let custody=removal_peer_poll_frame(context,local,peer,3,gate)?;
            check(custody.frames_bytes as usize==used,"removal-peer-ack-returned-bytes")?;
            // Pure DATA/Book checks only after full Ack. The next peer operation
            // is unconditionally WaitExit below, including on a local failure.
            removal_peer_transcript(context,local,transcript,ActionData::Send,&buffer[..used])?;
            buffer.fill(0);
            check(transcript.progress_data()==ProgressData::FramesExchanged && transcript.first_error_data().is_none(),
                "removal-peer-transcript-incomplete")?;
            Ok((preparation,nonce))
        }
        fn removal_peer_wait_exit(context:&RemovalPeerContext<'_>,local:&std::cell::RefCell<RemovalPeerLocal>,
            peer:&mut removal_peer_native::RemovalPeer<'_>,
            gate:&mut dyn FnMut(removal_peer_native::RemovalPeerCheckpoint)->native::android_service_management::Decision)->Result<()> {
            use removal_peer_native::{RemovalPeerOperation as Operation,RemovalPeerProgress as Progress};
            loop {
                local.borrow_mut().before_call_data(Operation::WaitExit)?;
                let progress=peer.poll_original_exit(gate);let custody=peer.custody();local.borrow_mut().observe(custody);
                if local.borrow().first.is_none() {
                    // A successful original exit must still fit the positive
                    // work cutoff. Hard reserve permits failure settlement only.
                    let effects=local.borrow().effects;
                    if let Err(error)=context.post(&effects) { local.borrow_mut().note(error); }
                }
                if progress==Progress::Ready {
                    check(custody.actual_exit_observed && removal_peer_complete_data(3,custody)
                        && !custody.unknown && !custody.failed,"removal-peer-original-exit")?;
                    return Ok(());
                }
                check(progress==Progress::Pending && !custody.unknown && !custody.actual_exit_observed,
                    "removal-peer-original-exit-refused")?;
                removal_peer_pending_wait(context,local,false)?;
            }
        }
        fn removal_peer_scoped(context:&RemovalPeerContext<'_>,effects:RemovalPeerOwnEffects,
            originals:removal_peer_native::RemovalSourceOriginals<'_>,ready_hint:fn(&str)->Result<()>)->RemovalPeerScope {
            use std::panic::{catch_unwind,AssertUnwindSafe};
            use removal_peer_native::{RemovalPeer,RemovalPeerOperation as Operation};
            let local=std::cell::RefCell::new(RemovalPeerLocal::new(effects));
            let mut gate=|point|context.checkpoint(&local,point);
            // Parent pending=true was stored BEFORE this actual constructor.
            let constructed=catch_unwind(AssertUnwindSafe(||RemovalPeer::parent(originals,context.request.native,&mut gate)));
            let mut peer=match constructed {
                Ok(peer)=>peer,
                Err(_)=>return RemovalPeerScope { proof:None,preparation:None,app_nonce:None,effects,
                    first:Some("removal-peer-constructor-unwind"),native_first:local.borrow().native_first,
                    custody:local.borrow().last,settled:false },
            };
            local.borrow_mut().observe(peer.custody());
            let mut transcript=removal_protocol::TranscriptData::new_data(removal_protocol::RoleData::Parent,
                context.request.data.binding_data().clone());
            let mut buffer=[0u8;removal_protocol::FRAME_LIMIT];
            let mut preparation=None;let mut app_nonce=None;
            let forward=catch_unwind(AssertUnwindSafe(|| {
                context.storage(Some(&transcript),None)?;
                removal_peer_forward(context,&local,&mut peer,&mut transcript,&mut buffer,ready_hint,&mut gate)
            }));
            match forward {
                Ok(Ok((branch,nonce)))=>{preparation=Some(branch);app_nonce=Some(nonce);},
                Ok(Err(error))=>local.borrow_mut().note(error),
                Err(_)=>local.borrow_mut().note("removal-peer-forward-unwind"),
            }
            local.borrow_mut().observe(peer.custody());buffer.fill(0);
            if local.borrow().first.is_some() { transcript.abort_data(); }
            // Even if final-send POST or transcript work failed, an actually
            // completed Ack means this SAME WatchExit must be the next call.
            if local.borrow().ack_complete {
                match catch_unwind(AssertUnwindSafe(||removal_peer_wait_exit(context,&local,&mut peer,&mut gate))) {
                    Ok(Ok(()))=>(),Ok(Err(error))=>local.borrow_mut().note(error),
                    Err(_)=>local.borrow_mut().note("removal-peer-exit-unwind"),
                }
                local.borrow_mut().observe(peer.custody());
            }
            let mut proof=None;
            if !peer.settled() {
                // One actual close call, never retry a consuming error. Each
                // independently known native slot is accounted by native3.
                let closed=catch_unwind(AssertUnwindSafe(|| {
                    local.borrow_mut().before_call_data(Operation::Close)?;
                    let progress=peer.close(&mut gate);
                    removal_peer_returned(&local,&peer,progress).map(|_|())
                }));
                match closed { Ok(Ok(()))=>(),Ok(Err(error))=>local.borrow_mut().note(error),
                    Err(_)=>local.borrow_mut().note("removal-peer-close-unwind") }
                local.borrow_mut().observe(peer.custody());
                // A refused operation can still have genuinely closed all
                // resources. Retire that known cell once; its None result is
                // failure-only finality, never permission to take M.
                if peer.custody().native_closed && !peer.custody().unknown && !peer.is_retired() {
                    match catch_unwind(AssertUnwindSafe(||peer.retire(&mut gate))) {
                        Ok(Ok(returned))=>proof=returned,
                        Ok(Err(_))=>local.borrow_mut().note("removal-peer-retire-refused"),
                        Err(_)=>local.borrow_mut().note("removal-peer-retire-unwind"),
                    }
                }
            }
            let custody=peer.custody();local.borrow_mut().observe(custody);
            let settled=removal_peer_known_retired_data(peer.settled(),custody);
            if !settled {
                local.borrow_mut().note("removal-peer-custody-retained");
                // No native Drop exists. Permanently abandon access to this
                // unknown cell; Parent pending retains the SAME raw4/Book FDs.
                // The synchronous callback was not retained by native code.
                std::mem::forget(peer);
            }
            drop(gate);
            let ledger=local.into_inner();
            RemovalPeerScope { proof,preparation,app_nonce,effects:ledger.effects,first:ledger.first,
                native_first:ledger.native_first,custody:Some(custody),settled }
        }
        // Same Parent ledger: initial snapshot+admission, then four fixed
        // immutable phase/failure records. No native borrow points into these
        // DATA buffers; Drop performs no filesystem work.
        struct RemovalSnapshotFile {
            writer:Option<usize>,reader:Option<usize>,written:u64,digest:Sha256,
            sealed:bool,persisted:bool,closed:bool,directory_persisted:bool,readback:bool,
        }
        impl RemovalSnapshotFile {
            fn new()->Self { Self { writer:None,reader:None,written:0,digest:Sha256::new(),
                sealed:false,persisted:false,closed:false,directory_persisted:false,readback:false } }
            fn settled_data(&self)->bool {
                self.writer.is_some() && self.reader.is_some() && self.written>0 && self.sealed
                    && self.persisted && self.closed && self.directory_persisted && self.readback
            }
        }
        struct RemovalSnapshot {
            capture:maintenance::RemovalSnapshotCapture,archive:Option<usize>,name:String,
            files:[RemovalSnapshotFile;6],attempted:bool,record:Option<mobile_release_desktop::macos_remove_record::RemovalRecordData>,
        }
        // Private, non-Clone return of this original writer only; not serialized.
        struct RemovalSnapshotAdmission {
            archive:usize,snapshot:usize,record:usize,snapshot_sha256:String,record_sha256:String,
        }
        pub(super) fn removal_archive_name_data(name:&str)->bool {
            name.len()==40 && name.starts_with(".remove-") && removal_hex_data::<16>(&name[8..]).is_ok()
        }
        pub(super) fn removal_snapshot_root_delta_data(before:&[(String,u64)],after:&BTreeMap<String,u64>,name:&str,inode:u64)->bool {
            removal_archive_name_data(name) && inode!=0 && !before.iter().any(|(n,_)|n==name)
                && after.len()==before.len()+1 && after.get(name)==Some(&inode)
                && before.iter().all(|(n,i)|after.get(n)==Some(i))
        }
        fn removal_snapshot_initial_history_data(count:usize,sealed_admission:bool)->bool {
            count<64 && !sealed_admission
        }
        fn removal_snapshot_budget_data(control:u64,storage:u64,snapshot:u64,originals:usize,capacity:usize,
            controls:usize,directories:usize,prior:usize,live:usize,external:usize)->Result<(usize,u64)> {
            check(controls<=488 && directories<=75 && prior<64 && snapshot>0
                && snapshot<=maintenance::REMOVAL_SNAPSHOT_LIMIT,"removal-snapshot-budget")?;
            let future=controls.checked_mul(3).and_then(|n|n.checked_add(directories*2+prior*8+16)).ok_or("removal-snapshot-budget")?;
            let end=originals.checked_add(future).filter(|n|*n<=24576).ok_or("removal-snapshot-budget")?;
            let table=if end>capacity { end.checked_mul(std::mem::size_of::<Original>()).ok_or("removal-snapshot-budget")? } else { 0 };
            let extra=table.checked_add(future.checked_mul(255).ok_or("removal-snapshot-budget")?).ok_or("removal-snapshot-budget")?;
            let bound=control.checked_add(extra as u64).filter(|n|*n<=16*1024*1024).ok_or("removal-snapshot-budget")?;
            check(storage.checked_add(snapshot).and_then(|n|n.checked_add(mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64))
                    .is_some_and(|n|n<=installation_record::PAYLOAD_LIMIT)
                && live.checked_add(external).and_then(|n|n.checked_add(6)).is_some_and(|n|n<=96),"removal-snapshot-budget")?;
            Ok((future,bound))
        }
        impl RemovalSnapshot {
            fn new(capture:maintenance::RemovalSnapshotCapture)->Self {
                Self { capture,archive:None,name:String::new(),files:std::array::from_fn(|_|RemovalSnapshotFile::new()),attempted:false,record:None }
            }
            fn row_post(book:&Install,row:&maintenance::RemovalSnapshotControl,n:usize)->Result<()> {
                let original=book.originals.get(n).ok_or("removal-snapshot-control-original")?;
                let role=match row.kind { 0|1|2=>Role::Reader,3=>Role::ReservationParticipant,4=>Role::GateParticipant,
                    _=>return Err("removal-snapshot-control-role") };
                check(original.state==State::Owned && original.role==role,"removal-snapshot-control-role")?;
                book.check_name(n,true)?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-control-stat")?;
                check(Identity::of(&actual)==row.identity && actual.st_flags==row.flags
                    && row.identity.size>=0 && row.identity.size as u64==row.size,"removal-snapshot-control-original")?;
                book.clock()
            }
            fn opened_directory(book:&mut Install,capture:&maintenance::RemovalSnapshotCapture,path:&str)->Result<usize> {
                let (parent,name)=match path.split_once('/') {
                    None=>(capture.root,path),
                    Some(("versions",release)) if !release.contains('/') => (capture.versions_original()?,release),
                    _=>return Err("removal-snapshot-directory-location"),
                };
                let n=book.open(Some(parent),name,true)?;
                let (identity,flags)=capture.directory_identity(path)?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-directory-stat")?;
                check(book.identity(n)?==identity && Identity::of(&actual)==identity && actual.st_flags==flags,
                    "removal-snapshot-directory-original")?;
                book.protected(n,true,Some(if path.starts_with(".install-"){0o700}else{0o755}))?;
                native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-snapshot-directory-attributes")?;Ok(n)
            }
            fn control_reader(book:&mut Install,capture:&maintenance::RemovalSnapshotCapture,row:&maintenance::RemovalSnapshotControl)
                ->Result<(usize,Option<usize>,bool)> {
                if let Some(n)=row.held { Self::row_post(book,row,n)?;return Ok((n,None,false)); }
                check(row.kind==0 && !row.path.starts_with('@'),"removal-snapshot-control-location")?;
                let (parent,opened,name)=match row.path.rsplit_once('/') {
                    None=>(capture.root,None,row.path.as_str()),
                    Some((directory,name))=>{
                        let original=Self::opened_directory(book,capture,directory)?;(original,Some(original),name)
                    },
                };
                let n=book.open(Some(parent),name,false)?;book.protected(n,false,Some(0o444))?;
                native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-snapshot-control-attributes")?;
                Self::row_post(book,row,n)?;Ok((n,opened,true))
            }
            fn create(&mut self,book:&mut Install,slot:usize)->Result<()> {
                let directory=self.archive.ok_or("removal-snapshot-archive")?;
                let name=removal_payload_file_name(slot)?;
                check(slot<6 && self.files[slot].writer.is_none(),"removal-snapshot-file-once")?;
                book.absent(directory,name)?;
                let before=RemovalPublication::parent_before(book,directory)?;
                let n=book.create_file(directory,name,Role::ReceiptWriter)?;
                self.files[slot].writer=Some(n); // Actual handle before later veto.
                let id=book.identity(n)?;
                check(id.mode==0o100600 && id.uid==0 && id.gid==0 && id.links==1 && id.size==0,
                    "removal-snapshot-private-writer")?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-writer-stat")?;
                check(actual.st_flags==0,"removal-snapshot-writer-flags")?;
                native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-snapshot-writer-attributes")?;
                RemovalPublication::returned_parent_change(book,directory,before,true)
            }
            fn write(&mut self,book:&mut Install,slot:usize,mut bytes:&[u8])->Result<()> {
                let file=&mut self.files[slot];let n=file.writer.ok_or("removal-snapshot-writer")?;
                let bound=if slot==0 {maintenance::REMOVAL_SNAPSHOT_LIMIT}else{mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64};
                check(file.written.checked_add(bytes.len() as u64).is_some_and(|n|n<=bound),"removal-snapshot-write-bound")?;
                while !bytes.is_empty() {
                    book.clock()?;
                    let count=unistd::write(book.fd(n)?,bytes).map_err(|_|"removal-snapshot-write")?;
                    check(count>0 && count<=bytes.len(),"removal-snapshot-write-bound")?;
                    file.written+=count as u64;file.digest.update(&bytes[..count]);bytes=&bytes[count..];
                    // Retain the actual returned bytes before a late clock cut.
                    book.clock()?;
                }
                Ok(())
            }
            fn close_file(&mut self,book:&mut Install,slot:usize)->Result<()> {
                let directory=self.archive.ok_or("removal-snapshot-archive")?;
                let file=&mut self.files[slot];let n=file.writer.ok_or("removal-snapshot-writer")?;
                let before=book.identity(n)?;let original=&book.originals[n];
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-written-stat")?;
                let named=book.named(original.parent,&original.name).map_err(|_|"removal-snapshot-written-name")?;
                check(before.same_object(Identity::of(&actual)) && actual.st_mode==0o100600 && actual.st_nlink==1
                    && actual.st_size==file.written as i64 && actual.st_flags==0 && named.st_flags==0
                    && Identity::of(&actual)==Identity::of(&named),"removal-snapshot-written-original")?;
                book.clock()?;
                stat::fchmod(book.fd(n)?,Mode::from_bits_truncate(0o444)).map_err(|_|"removal-snapshot-seal")?;
                file.sealed=true;book.clock()?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-sealed-stat")?;
                let original=&book.originals[n];
                let named=book.named(original.parent,&original.name).map_err(|_|"removal-snapshot-sealed-name")?;
                check(before.same_object(Identity::of(&actual)) && actual.st_mode==0o100444 && actual.st_nlink==1
                    && actual.st_size==file.written as i64 && actual.st_flags==0 && named.st_flags==0
                    && Identity::of(&actual)==Identity::of(&named),"removal-snapshot-sealed-original")?;
                book.originals[n].identity=Some(Identity::of(&actual));
                book.protected(n,false,Some(0o444))?;
                native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-snapshot-file-attributes")?;
                book.clock()?;let persisted=native::sync(book.fd(n)?.as_fd(),true);
                file.persisted=persisted.is_ok();persisted.map_err(|_|"removal-snapshot-file-persist")?;book.clock()?;
                file.closed=book.close(n);check(file.closed,"removal-snapshot-writer-close")?;book.clock()?;
                let name=removal_payload_file_name(slot)?;
                let reader=book.open(Some(directory),name,false)?;file.reader=Some(reader);
                check(book.identity(reader)?==Identity::of(&actual),"removal-snapshot-readback-original")?;
                book.protected(reader,false,Some(0o444))?;
                native::no_xattrs(book.fd(reader)?.as_fd()).map_err(|_|"removal-snapshot-file-attributes")?;
                let digest=format!("{:x}",file.digest.clone().finalize());
                check(book.read(reader,file.written,false)?.0==digest,"removal-snapshot-readback")?;
                check(stat::fstat(book.fd(reader)?).map_err(|_|"removal-snapshot-readback-stat")?.st_flags==0,
                    "removal-snapshot-readback-flags")?;
                file.readback=true;book.clock()?;
                let persisted=native::sync(book.fd(directory)?.as_fd(),false);
                file.directory_persisted=persisted.is_ok();persisted.map_err(|_|"removal-snapshot-directory-persist")?;
                book.clock()
            }
            fn census_post(&self,book:&mut Install)->Result<()> {
                let archive=self.archive.ok_or("removal-snapshot-archive")?;
                self.capture.census_post(book,&self.name,book.identity(archive)?.ino)?;
                let directory=book.open(Some(self.capture.root),&self.name,true)?;
                check(book.identity(directory)?==book.identity(archive)?,"removal-snapshot-archive-original")?;
                book.protected(directory,true,Some(0o700))?;
                native::no_xattrs(book.fd(directory)?.as_fd()).map_err(|_|"removal-snapshot-archive-attributes")?;
                check(stat::fstat(book.fd(directory)?).map_err(|_|"removal-snapshot-archive-stat")?.st_flags==0,
                    "removal-snapshot-archive-flags")?;
                let roster=book.roster(directory)?;
                check(roster.len()==2 && roster.get("snapshot-v2")==Some(&book.identity(self.files[0].reader.ok_or("removal-snapshot-reader")?)?.ino)
                    && roster.get("admission.json")==Some(&book.identity(self.files[1].reader.ok_or("removal-snapshot-reader")?)?.ino),
                    "removal-snapshot-archive-roster")?;
                book.check_name(directory,true)?;book.forward_close(directory,"removal-snapshot-census-close")?;
                book.absent(archive,"app")?;book.check_name(archive,true)
            }
            fn prepare(&mut self,book:&mut Install,source:&RemovalAdmission,observed:&maintenance::RemovalObserved,
                request:&RemovalRequest,exclusion:&RemovalExclusion)->Result<RemovalSnapshotAdmission> {
                check(!self.attempted && self.capture.complete,"removal-snapshot-once")?;self.attempted=true;
                let prior=self.capture.prior_archives()?;
                check(removal_snapshot_initial_history_data(prior.rows().len(),prior.rows().iter()
                    .any(|r|r.files()[1].as_ref().is_some_and(|f|f.shape_tag_data()==2))),"removal-snapshot-admitted-history-unavailable")?;
                // This initial-admission slice cannot issue a previous=None
                // record over completed history. Linked resume must authenticate
                // and reuse the ORIGINAL payload snapshot commitment separately.
                exclusion.post(book,source)?;observed.post(book)?;
                let binding=request.data.binding_data().fields_data();
                check(request.native==removal_native_binding_data(request.data.binding_data())?
                    && exclusion.peer.retired().binding_data()==&request.native,"removal-snapshot-request")?;
                self.name=format!(".remove-{}",binding.root_nonce);check(removal_archive_name_data(&self.name),"removal-snapshot-name")?;
                book.absent(self.capture.root,&self.name)?;
                for (n,raw) in source.originals.installed_pair.iter().zip(&source.originals.installed_raw) { self.capture.held(book,*n,raw,0)?; }
                self.capture.held(book,source.originals.input.removal_signed_originals_data()?[0],source.originals.input.descriptor_data(),1)?;
                self.capture.held(book,source.originals.input.removal_signed_originals_data()?[1],source.originals.input.signature_data(),2)?;
                self.capture.held(book,exclusion.reservation,paths::REGISTRATION_GATE_BYTES,3)?;
                self.capture.held(book,exclusion.maintenance,paths::MAINTENANCE_GATE_BYTES,4)?;
                self.capture.controls.sort_by(|a,b|a.path.cmp(&b.path));
                let selected=source.current_selection(book)?.encode_data().map_err(|_|"removal-snapshot-selection")?;
                let state_sha=format!("{:x}",Sha256::digest(observed.snapshot_state_bytes()?));
                let header=self.capture.header(request.data.binding_data(),&state_sha,&selected,
                    selected.capacity()+self.name.capacity()+std::mem::size_of::<Self>())?;
                let mut total=header.len() as u64;
                for row in &self.capture.controls {
                    total=total.checked_add(maintenance::removal_snapshot_frame_data(row)?.len() as u64)
                        .and_then(|n|n.checked_add(row.size)).ok_or("removal-snapshot-size")?;
                }
                self.capture.memory(header.capacity()+selected.capacity()+self.name.capacity()+std::mem::size_of::<Self>())?;
                let (control,storage)=self.capture.quote.ok_or("removal-snapshot-quote")?;
                let old_capacity=book.originals.capacity();
                let (future,bound)=removal_snapshot_budget_data(control,storage,total,book.originals.len(),old_capacity,
                    self.capture.controls.len(),self.capture.directory_count(),self.capture.prior_archives()?.rows().len(),book.originals.iter().filter(|r|r.fd.is_some()).count(),book.removal_live_reserved)?;
                let delta=bound.checked_sub(control).ok_or("removal-snapshot-budget")?;
                book.removal_control_reserved=book.removal_control_reserved.checked_add(delta)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-control-bound")?;
                // Same table, not a second owner. Account possible reallocation
                // overlap before requesting growth; verify actual returned capacity.
                book.originals.try_reserve_exact(future).map_err(|_|"removal-snapshot-allocation")?;
                let needed=book.originals.len().checked_add(future).ok_or("removal-snapshot-budget")?;
                check(book.originals.capacity()<=old_capacity.max(needed),"removal-snapshot-table-capacity")?;
                let before=RemovalPublication::parent_before(book,self.capture.root)?;
                let root_reader=book.open(book.originals[self.capture.root].parent,&book.originals[self.capture.root].name.clone(),true)?;
                check(book.identity(root_reader)?==before.0,"removal-snapshot-root-original")?;
                let names=book.roster(root_reader)?;
                check(names.len()==self.capture.root_children()?.len()
                    && self.capture.root_children()?.iter().all(|(n,i)|names.get(n)==Some(i)),"removal-snapshot-root-census")?;
                book.check_name(root_reader,true)?;book.forward_close(root_reader,"removal-snapshot-root-close")?;
                exclusion.post(book,source)?;observed.post(book)?;
                let effect=book.creations.len();
                let archive=book.directory(self.capture.root,&self.name,true,0o700)?;
                self.archive=Some(archive);
                let created=book.identity(archive)?;
                check(book.creations.get(effect).is_some_and(|c|c.parent==self.capture.root && c.name==self.name
                    && c.state=="created" && c.identity==Some(created)),"removal-snapshot-directory-effect")?;
                check(stat::fstat(book.fd(archive)?).map_err(|_|"removal-snapshot-archive-stat")?.st_flags==0,"removal-snapshot-archive-flags")?;
                RemovalPublication::returned_parent_change(book,self.capture.root,before,true)?;
                exclusion.post(book,source)?;observed.post(book)?;
                self.create(book,0)?;self.write(book,0,&header)?;drop(header);drop(selected);
                for index in 0..self.capture.controls.len() {
                    exclusion.post(book,source)?;
                    let frame=maintenance::removal_snapshot_frame_data(&self.capture.controls[index])?;
                    let (reader,parent,close_reader)=Self::control_reader(book,&self.capture,&self.capture.controls[index])?;
                    self.write(book,0,&frame)?;
                    let expected=self.capture.controls[index].size;let mut at=0u64;let mut hash=Sha256::new();let mut block=[0u8;65536];
                    while at<expected {
                        book.clock()?;let length=usize::try_from((expected-at).min(block.len() as u64)).map_err(|_|"removal-snapshot-copy-bound")?;
                        let used=nix::sys::uio::pread(book.fd(reader)?,&mut block[..length],at as i64).map_err(|_|"removal-snapshot-copy-read")?;
                        check(used>0 && used<=length,"removal-snapshot-copy-size")?;
                        at+=used as u64;hash.update(&block[..used]);self.write(book,0,&block[..used])?;
                    }
                    let mut eof=[0];book.clock()?;
                    check(nix::sys::uio::pread(book.fd(reader)?,&mut eof,at as i64).map_err(|_|"removal-snapshot-copy-eof")?==0
                        && <[u8;32]>::from(hash.finalize())==self.capture.controls[index].digest,"removal-snapshot-copy-hash")?;
                    Self::row_post(book,&self.capture.controls[index],reader)?;
                    if close_reader { book.forward_close(reader,"removal-snapshot-control-close")?; }
                    if let Some(parent)=parent { book.check_name(parent,true)?;book.forward_close(parent,"removal-snapshot-control-parent-close")?; }
                    exclusion.post(book,source)?;
                }
                check(self.files[0].written==total,"removal-snapshot-size")?;self.close_file(book,0)?;
                check(self.files[0].settled_data(),"removal-snapshot-original-finality")?;
                maintenance::post_removal_archive_census(book,self.capture.prior_archives()?)?;
                exclusion.post(book,source)?;observed.post(book)?;
                let snapshot_sha=format!("{:x}",self.files[0].digest.clone().finalize());
                use mobile_release_desktop::macos_remove_record::{RemovalBindingData,RemovalRecordData};
                let binding_data=RemovalBindingData { target:source.current_selection(book)?.target_data(),source_commit:binding.source_commit,
                    removal_descriptor_sha256:binding.remove_producer_sha256,installed_producer_sha256:binding.installed_producer_sha256,
                    installed_inventory_sha256:binding.installed_inventory_sha256,installation_state_sha256:&state_sha,payload_roster_sha256:&snapshot_sha };
                self.record=Some(RemovalRecordData::admission_data(binding.request_id,binding.root_nonce,binding_data)
                    .map_err(|_|"removal-snapshot-record")?);
                // The bounded bytes copy avoids overlapping mutable self with
                // the immutable original record; it is in the reserved codec cell.
                let raw=self.record.as_ref().ok_or("removal-snapshot-record")?.bytes_data().to_vec();
                self.create(book,1)?;self.write(book,1,&raw)?;self.close_file(book,1)?;
                maintenance::held_bytes(book,self.files[1].reader.ok_or("removal-snapshot-reader")?,&raw)?;
                let parsed=RemovalRecordData::parse_data(&raw,binding_data).map_err(|_|"removal-snapshot-record-readback")?;
                check(parsed.digest_data()==self.record.as_ref().ok_or("removal-snapshot-record")?.digest_data(),"removal-snapshot-record-readback")?;
                self.census_post(book)?;
                self.file_post(book,0)?;self.file_post(book,1)?;
                exclusion.post(book,source)?;observed.post(book)?;
                check(self.files[..2].iter().all(RemovalSnapshotFile::settled_data),"removal-snapshot-original-finality")?;
                Ok(RemovalSnapshotAdmission { archive,snapshot:self.files[0].reader.ok_or("removal-snapshot-reader")?,
                    record:self.files[1].reader.ok_or("removal-snapshot-reader")?,snapshot_sha256:snapshot_sha,
                    record_sha256:parsed.digest_data().to_owned() })
            }
        }

        impl RemovalSnapshot {
            fn file_post(&self,book:&Install,slot:usize)->Result<()> {
                let file=&self.files[slot];check(file.settled_data(),"removal-snapshot-original-finality")?;
                let n=file.reader.ok_or("removal-snapshot-reader")?;
                book.check_name(n,true)?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-final-stat")?;
                check(actual.st_flags==0 && actual.st_mode==0o100444 && actual.st_nlink==1
                    && actual.st_size==file.written as i64,"removal-snapshot-final-original")?;
                let mut at=0u64;let mut hash=Sha256::new();let mut block=[0;65536];
                loop {
                    book.clock()?;
                    let count=nix::sys::uio::pread(book.fd(n)?,&mut block,at as i64).map_err(|_|"removal-snapshot-final-read")?;
                    if count==0 { break; }
                    at=at.checked_add(count as u64).filter(|n|*n<=file.written).ok_or("removal-snapshot-final-size")?;
                    hash.update(&block[..count]);
                }
                check(at==file.written && hash.finalize()==file.digest.clone().finalize(),"removal-snapshot-final-hash")?;
                book.check_name(n,true)?;
                check(stat::fstat(book.fd(n)?).map_err(|_|"removal-snapshot-final-stat")?.st_flags==0,"removal-snapshot-final-flags")?;
                book.clock()
            }
        }

        #[derive(Clone,Copy,PartialEq,Eq)]
        enum RemovalPayloadPhase { OriginalSource, Transferred, AppWithdrawn, Removing, Absent }
        #[derive(Clone,Copy,PartialEq,Eq)]
        enum RemovalNodeEffect { Present, Removed, Unknown }
        struct RemovalNodeState { original:Option<usize>,effect:RemovalNodeEffect,roster_observed:bool,
            returned:Option<std::result::Result<(),i32>> }
        struct RemovalPayloadExecution {
            source:RemovalAdmission, observed:maintenance::RemovalObserved, snapshot:RemovalSnapshot,
            admission:RemovalSnapshotAdmission, exclusion:RemovalExclusion, plan:maintenance::RemovalPayloadPlan,
            phase:RemovalPayloadPhase, states:Vec<RemovalNodeState>, release_originals:Vec<usize>,
            record:Option<mobile_release_desktop::macos_remove_record::RemovalRecordData>,
            pending_record:Option<(usize,mobile_release_desktop::macos_remove_record::RemovalRecordData)>,
            failure_record:Option<mobile_release_desktop::macos_remove_record::RemovalRecordData>,
            first:Option<(&'static str,mobile_release_desktop::macos_remove_record::FailureKindData)>,
            attempted:bool,remaining_originals:usize,ancestor_flags:[u32;4],
            withdrawal_return:Option<std::result::Result<(),Option<i32>>>,
        }
        struct RemovalPayloadAbsence { archive:usize,record:usize,snapshot:usize,record_sha256:String }
        fn removal_payload_originals_data(files:usize,directories:usize,controls:usize,prior:usize)->Option<usize> {
            if files>9*installation_record::FILE_LIMIT || directories>9*installation_record::FILE_LIMIT
                || controls>75 || prior>=64 {return None;}
            files.checked_mul(2)?.checked_add(directories.checked_mul(3)?)?
                .checked_add(controls.checked_mul(2)?)?.checked_add(prior.checked_mul(8)?)?.checked_add(32)
        }
        fn removal_payload_original_budget_data(used:usize,files:usize,directories:usize,controls:usize,prior:usize)->Option<(usize,usize)> {
            let future=removal_payload_originals_data(files,directories,controls,prior)?;
            let end=used.checked_add(future).filter(|n|*n<=24576)?;Some((future,end))
        }
        fn removal_payload_allocation_data(control:u64,extra:usize,storage:u64,snapshot:u64)->bool {
            control.checked_add(extra as u64).is_some_and(|n|n<=16*1024*1024)
                && storage.checked_add(snapshot).and_then(|n|n.checked_add(5*mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64))
                    .is_some_and(|n|n<=installation_record::PAYLOAD_LIMIT)
        }
        fn removal_payload_live_data(live:usize,external:usize)->bool {
            // Depth<=17 directories plus one leaf/roster; ONE generation
            // anchor; four progress readbacks; two fixed census margins.
            // These alternatives conservatively total25, reserve26 unchanged.
            live.checked_add(external).and_then(|n|n.checked_add(26)).is_some_and(|n|n<=96)
        }
        fn removal_payload_app_last_data(index:usize,current_app:usize,states:&[RemovalNodeState])->bool {
            index!=current_app || states.iter().enumerate().all(|(i,s)|i==current_app||s.effect==RemovalNodeEffect::Removed)
        }
        fn removal_payload_latch_data(first:&mut Option<(&'static str,mobile_release_desktop::macos_remove_record::FailureKindData)>,
            error:&'static str,kind:mobile_release_desktop::macos_remove_record::FailureKindData) {
            if first.is_none(){*first=Some((error,kind));}
        }
        fn removal_payload_children_data<'a>(children:impl Iterator<Item=(&'a str,u64,RemovalNodeEffect)>,actual:&BTreeMap<String,u64>)->bool {
            let mut count=0;
            for (name,inode,effect) in children {
                match effect {
                    RemovalNodeEffect::Present=>{count+=1;if actual.get(name)!=Some(&inode){return false;}},
                    RemovalNodeEffect::Removed=>(),RemovalNodeEffect::Unknown=>return false,
                }
            }actual.len()==count
        }
        fn removal_payload_sealed_record_data(record_bytes:usize,written:u64,sealed_returned:bool,raw_hash_matches:bool)->bool {
            record_bytes>0 && record_bytes<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT
                && written==record_bytes as u64 && sealed_returned && raw_hash_matches
        }
        fn removal_payload_phase_allows_unlink_data(phase:RemovalPayloadPhase,deletion_record_settled:bool,first:bool)->bool {
            phase==RemovalPayloadPhase::Removing && deletion_record_settled && !first
        }
        fn removal_payload_parent_change_data(before:Identity,flags:u32,actual:Identity,actual_flags:u32,named:Identity,named_flags:u32)->bool {
            before.dev==actual.dev && before.ino==actual.ino && before.mode==actual.mode
                && before.uid==actual.uid && before.gid==actual.gid && flags==actual_flags && actual_flags==named_flags
                && actual==named && actual.mode&0o170000==0o040000
        }
        fn removal_payload_file_name(slot:usize)->Result<&'static str> {
            match slot {0=>Ok("snapshot-v2"),1=>Ok("admission.json"),2=>Ok("app-withdrawn.json"),
                3=>Ok("payload-roster-removal.json"),4=>Ok("payload-absent-observed.json"),5=>Ok("first-failure.json"),
                _=>Err("removal-payload-record-slot")}
        }
        impl RemovalPayloadExecution {
            fn new(source:RemovalAdmission,observed:maintenance::RemovalObserved,snapshot:RemovalSnapshot,
                admission:RemovalSnapshotAdmission,exclusion:RemovalExclusion,plan:maintenance::RemovalPayloadPlan)->Self {
                Self {source,observed,snapshot,admission,exclusion,plan,phase:RemovalPayloadPhase::OriginalSource,
                    states:Vec::new(),release_originals:Vec::new(),record:None,pending_record:None,failure_record:None,first:None,attempted:false,remaining_originals:0,ancestor_flags:[0;4],withdrawal_return:None}
            }
            fn root(&self)->usize {self.source.originals.code[3]}
            fn archive(&self)->usize {self.admission.archive}
            fn current_app(&self)->Result<usize> {self.plan.generations.first().and_then(|g|g.roots[0]).ok_or("removal-payload-current-app")}
            fn note(&mut self,error:&'static str,kind:mobile_release_desktop::macos_remove_record::FailureKindData) {
                removal_payload_latch_data(&mut self.first,error,kind);
            }
            fn external_post(&self,book:&Install)->Result<()> {
                check(self.phase!=RemovalPayloadPhase::OriginalSource && self.source.settled()
                    && self.source.first.is_none(),"removal-payload-source-phase")?;
                self.source.originals.input.post(book)?;
                for (slot,n) in self.source.originals.code[..4].iter().enumerate() {
                    book.check_name(*n,true)?;
                    check(stat::fstat(book.fd(*n)?).map_err(|_|"removal-payload-source-stat")?.st_flags==self.ancestor_flags[slot],"removal-payload-source-flags")?;
                }
                for (n,raw) in self.source.originals.installed_pair.iter().zip(&self.source.originals.installed_raw) {
                    maintenance::held_bytes(book,*n,raw)?;
                }
                let root=self.root();let r=self.exclusion.reservation;let m=self.exclusion.maintenance;
                check(book.registration.entered && book.registration.verified && book.registration.exclusive_acquired
                    && book.registration.lock_attempted && book.registration.parent==Some(root) && book.registration.participant==Some(r)
                    && !book.registration.closed_under_maintenance && book.gate.entered && book.gate.verified
                    && book.gate.exclusive_acquired && book.gate.lock_attempted && book.gate.parent==Some(root)
                    && book.gate.participant==Some(m) && self.source.existing_maintenance==Some(m),"removal-payload-exclusion")?;
                book.registration_protected(r)?;book.gate_protected(m)?;
                maintenance::held_bytes(book,r,paths::REGISTRATION_GATE_BYTES)?;
                maintenance::held_bytes(book,m,paths::MAINTENANCE_GATE_BYTES)?;
                let peer=self.exclusion.peer.retired();
                check(peer.original_peer_exit_observed() && peer.role()==native::removal_coordinator::RemovalPeerRole::Parent,
                    "removal-payload-peer-retirement")?;
                self.observed.payload_controls_post(book)?;
                for slot in 0..2 {
                    check(self.snapshot.files[slot].settled_data(),"removal-payload-snapshot-finality")?;
                    let n=self.snapshot.files[slot].reader.ok_or("removal-payload-snapshot-original")?;
                    book.check_name(n,true)?;
                    check(stat::fstat(book.fd(n)?).map_err(|_|"removal-payload-snapshot-stat")?.st_flags==0,"removal-payload-snapshot-flags")?;
                }
                book.clock()
            }
            fn original_open(&mut self,book:&mut Install,parent:Option<usize>,name:&str,directory:bool)->Result<usize> {
                check(self.remaining_originals>0,"removal-payload-original-budget")?;
                self.remaining_originals-=1;book.open(parent,name,directory)
            }
            fn roster(&mut self,book:&mut Install,parent:usize)->Result<BTreeMap<String,u64>> {
                let original=&book.originals[parent];let grandparent=original.parent;let name=original.name.clone();
                let reader=self.original_open(book,grandparent,&name,true)?;
                check(book.identity(parent)?.same_object(book.identity(reader)?),"removal-payload-roster-original")?;
                let found=book.roster(reader)?;book.check_name(reader,true)?;
                book.forward_close(reader,"removal-payload-roster-close")?;Ok(found)
            }
            fn remaining_children(&self,index:usize,actual:&BTreeMap<String,u64>)->bool {
                removal_payload_children_data(self.plan.nodes[index].children.iter().map(|child|{
                    let node=&self.plan.nodes[*child];(node.name.as_str(),node.identity.ino,self.states[*child].effect)
                }),actual)
            }
            fn namespace_matches(&self,parent:usize,book:&Install,actual:&BTreeMap<String,u64>)->Result<bool> {
                let identity=book.identity(parent)?;
                if let Some(index)=self.states.iter().enumerate().find_map(|(i,s)|s.original.filter(|n|
                    self.plan.nodes[i].directory && book.identity(*n).is_ok_and(|v|v.dev==identity.dev&&v.ino==identity.ino)).map(|_|i)) {
                    return Ok(self.remaining_children(index,actual));
                }
                if identity.same_object(book.identity(self.root())?) {
                    let old=self.snapshot.capture.root_children()?;let mut expected=BTreeMap::new();
                    for (name,inode) in old {
                        let removed=name==paths::APP_NAME && self.phase!=RemovalPayloadPhase::Transferred
                            || self.plan.generations.iter().enumerate().any(|(g,row)|g>0 && name==&row.app_name
                                && row.roots[0].is_some_and(|i|self.states[i].effect==RemovalNodeEffect::Removed));
                        if !removed{expected.insert(name.clone(),*inode);}
                    }
                    expected.insert(self.snapshot.name.clone(),book.identity(self.archive())?.ino);return Ok(*actual==expected);
                }
                if identity.same_object(book.identity(self.archive())?) {
                    let mut expected=BTreeMap::new();
                    for slot in 0..6 {
                        let file=&self.snapshot.files[slot];
                        if let Some(n)=file.reader.or(file.writer) {
                            expected.insert(removal_payload_file_name(slot)?.to_owned(),book.identity(n)?.ino);
                        }
                    }
                    let app=self.current_app()?;
                    if self.phase!=RemovalPayloadPhase::Transferred && self.states[app].effect==RemovalNodeEffect::Present {
                        expected.insert("app".to_owned(),self.plan.nodes[app].identity.ino);
                    }
                    return Ok(*actual==expected);
                }
                for (g,release) in self.release_originals.iter().enumerate() {
                    if identity.same_object(book.identity(*release)?) {
                        let path=format!("versions/{}",self.plan.generations[g].release);
                        let names=self.snapshot.capture.directory_children(&path)?;
                        let root=self.plan.generations[g].roots[1].ok_or("removal-payload-runtime-root")?;
                        let expected:BTreeMap<_,_>=names.iter().filter(|(name,_)|name!="runtime"||self.states[root].effect!=RemovalNodeEffect::Removed).cloned().collect();
                        return Ok(*actual==expected);
                    }
                }
                Err("removal-payload-parent-not-planned")
            }
            fn advance_parent(&mut self,book:&mut Install,parent:usize,before:(Identity,u32))->Result<()> {
                // The sole caller has already retained the actual returned own
                // effect. No unknown/nonzero return enters this baseline path.
                let actual=stat::fstat(book.fd(parent)?).map_err(|_|"removal-payload-parent-stat")?;
                let original=&book.originals[parent];let named=book.named(original.parent,&original.name).map_err(|_|"removal-payload-parent-name")?;
                check(removal_payload_parent_change_data(before.0,before.1,Identity::of(&actual),actual.st_flags,Identity::of(&named),named.st_flags),
                    "removal-payload-parent-effect")?;
                let roster=self.roster(book,parent)?;check(self.namespace_matches(parent,book,&roster)?,"removal-payload-parent-roster")?;
                // Only independently verified aliases of THIS actual parent
                // share this returned effect. Everything else stays exact.
                for n in 0..book.originals.len() {
                    if book.originals[n].fd.is_none(){continue;}
                    let old=book.identity(n)?;
                    if old.dev==before.0.dev && old.ino==before.0.ino {
                        let held=stat::fstat(book.fd(n)?).map_err(|_|"removal-payload-alias-stat")?;
                        let original=&book.originals[n];let named=book.named(original.parent,&original.name).map_err(|_|"removal-payload-alias-name")?;
                        check(removal_payload_parent_change_data(old,before.1,Identity::of(&held),held.st_flags,Identity::of(&named),named.st_flags)
                            && Identity::of(&held)==Identity::of(&actual),"removal-payload-alias-effect")?;
                        book.originals[n].identity=Some(Identity::of(&held));
                    }
                }
                for (i,state) in self.states.iter().enumerate() {
                    if state.original.is_some_and(|n|book.identity(n).is_ok_and(|id|id.dev==before.0.dev&&id.ino==before.0.ino)) {
                        self.plan.nodes[i].identity=Identity::of(&actual);
                    }
                }
                native::no_xattrs(book.fd(parent)?.as_fd()).map_err(|_|"removal-payload-parent-attributes")?;
                book.check_name(parent,true)?;book.clock()
            }
            fn transfer(&mut self,book:&mut Install)->Result<()> {
                check(!self.attempted && self.phase==RemovalPayloadPhase::OriginalSource && self.plan.complete,"removal-payload-once")?;
                self.attempted=true;self.exclusion.post(book,&self.source)?;self.observed.post(book)?;
                check(self.source.settled() && self.source.first.is_none()
                    && self.snapshot.files[..2].iter().all(RemovalSnapshotFile::settled_data)
                    && self.snapshot.archive==Some(self.admission.archive)
                    && self.snapshot.files[0].reader==Some(self.admission.snapshot)
                    && self.snapshot.files[1].reader==Some(self.admission.record)
                    && format!("{:x}",self.snapshot.files[0].digest.clone().finalize())==self.admission.snapshot_sha256,
                    "removal-payload-admission")?;
                self.snapshot.file_post(book,0)?;self.snapshot.file_post(book,1)?;
                let record=self.snapshot.record.take().ok_or("removal-payload-admission")?;
                check(record.digest_data()==self.admission.record_sha256 && record.prefix_data()==mobile_release_desktop::macos_remove_record::PrefixData::AdmissionRecorded
                    && record.first_failure_data().is_none(),"removal-payload-admission")?;self.record=Some(record);
                let (files,directories)=self.plan.nodes.iter().fold((0usize,0usize),|(f,d),n|if n.directory{(f,d+1)}else{(f+1,d)});
                let (future,end)=removal_payload_original_budget_data(book.originals.len(),files,directories,
                    self.snapshot.capture.directory_count(),self.snapshot.capture.prior_archives()?.rows().len())
                    .ok_or("removal-payload-original-budget")?;
                let old_capacity=book.originals.capacity();
                let table=if end>old_capacity{end.checked_mul(std::mem::size_of::<Original>()).ok_or("removal-payload-memory")?}else{0};
                let states=self.plan.nodes.len().checked_mul(std::mem::size_of::<RemovalNodeState>()).ok_or("removal-payload-memory")?;
                // One bounded roster/hash/progress working cell, not a new cap.
                let working=2*1024*1024+states+9*std::mem::size_of::<usize>()+std::mem::size_of::<Self>();
                let extra=table.checked_add(future.checked_mul(255).ok_or("removal-payload-memory")?)
                    .and_then(|n|n.checked_add(working)).ok_or("removal-payload-memory")?;
                let (_,storage)=self.snapshot.capture.quote.ok_or("removal-payload-budget")?;
                let control=book.removal_observation_control.ok_or("removal-payload-budget")?
                    .checked_add(book.removal_control_reserved.checked_sub(book.removal_observation_reserved)
                        .ok_or("removal-payload-budget")?).ok_or("removal-payload-budget")?;
                check(removal_payload_allocation_data(control,extra,storage,self.snapshot.files[0].written),"removal-payload-budget")?;
                book.removal_control_reserved=book.removal_control_reserved.checked_add(extra as u64)
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-payload-memory")?;
                book.originals.try_reserve_exact(future).map_err(|_|"removal-payload-allocation")?;
                check(book.originals.capacity()<=old_capacity.max(end),"removal-payload-allocation")?;
                self.states.try_reserve_exact(self.plan.nodes.len()).map_err(|_|"removal-payload-allocation")?;
                self.release_originals.try_reserve_exact(9).map_err(|_|"removal-payload-allocation")?;
                check(self.states.capacity()<=self.plan.nodes.len() && self.release_originals.capacity()<=9,"removal-payload-allocation")?;
                self.states.extend(self.plan.nodes.iter().map(|_|RemovalNodeState {original:None,effect:RemovalNodeEffect::Present,roster_observed:false,returned:None}));
                self.remaining_originals=future;
                let app=self.current_app()?;let original=self.plan.nodes[app].held.ok_or("removal-payload-current-app")?;
                check(!self.source.originals.code.contains(&original) && book.identity(original)?==self.plan.nodes[app].identity
                    && book.originals[original].parent==Some(self.root()) && book.originals[original].name==paths::APP_NAME,
                    "removal-payload-current-app")?;
                self.states[app].original=Some(original);
                // Native five + peer are retired; no callback can borrow these
                // now-consumed code originals. The external package stays held.
                for n in self.source.originals.code[4..].iter().copied().rev() {
                    check(n!=original && !self.source.originals.installed_pair.contains(&n)
                        && n!=self.exclusion.maintenance && n!=self.exclusion.reservation,"removal-payload-source-alias")?;
                    book.check_name(n,true)?;book.forward_close(n,"removal-payload-code-close")?;
                }
                // The first observation may have retained another app-root
                // alias. No live child may depend on it; retire it rather than
                // carrying an obsolete pre-withdrawal pathname into settlement.
                for alias in 0..book.originals.len() {
                    if alias==original || book.originals[alias].fd.is_none(){continue;}
                    if book.identity(alias)?.same_object(self.plan.nodes[app].identity) {
                        check(book.identity(alias)?==self.plan.nodes[app].identity
                            && book.originals[alias].parent==Some(self.root()) && book.originals[alias].name==paths::APP_NAME
                            && !book.originals.iter().any(|r|r.fd.is_some()&&r.parent==Some(alias)),"removal-payload-app-alias")?;
                        book.check_name(alias,true)?;book.forward_close(alias,"removal-payload-app-alias-close")?;
                    }
                }
                let external=book.removal_live_reserved.checked_add(if book.worker_deadline.is_some(){EXTRA_LIVE}else{0})
                    .ok_or("removal-payload-live-budget")?;
                check(removal_payload_live_data(book.originals.iter().filter(|r|r.fd.is_some()).count(),external),
                    "removal-payload-live-budget")?;
                for (slot,n) in self.source.originals.code[..4].iter().enumerate() {
                    self.ancestor_flags[slot]=stat::fstat(book.fd(*n)?).map_err(|_|"removal-payload-source-stat")?.st_flags;
                }
                self.phase=RemovalPayloadPhase::Transferred;self.external_post(book)?;
                self.external_post(book)
            }
            fn failure_basis(&self)->Result<&mobile_release_desktop::macos_remove_record::RemovalRecordData> {
                if let Some((slot,record))=&self.pending_record {
                    let file=&self.snapshot.files[*slot];
                    // Actual complete writes + returned seal describe the
                    // record a fresh reader may see, NOT fsync/close success.
                    if removal_payload_sealed_record_data(record.bytes_data().len(),file.written,file.sealed,
                        format!("{:x}",file.digest.clone().finalize())==record.digest_data()) {return Ok(record);}
                }
                self.record.as_ref().ok_or("removal-payload-record")
            }
            fn progress(&mut self,book:&mut Install,slot:usize)->Result<()> {
                use mobile_release_desktop::macos_remove_record::{RemovalRecordData,PrefixData,RemovalBindingData};
                self.external_post(book)?;check((2..=5).contains(&slot),"removal-payload-record-slot")?;
                check(if slot==5{self.failure_record.is_none()}else{self.pending_record.is_none() && self.first.is_none()},
                    "removal-payload-record-once")?;
                let old=if slot==5{self.failure_basis()?}else{self.record.as_ref().ok_or("removal-payload-record")?};
                let descriptor=self.source.descriptor.as_ref().ok_or("removal-payload-source")?;
                let fields=self.source.removal.as_ref().ok_or("removal-payload-source")?.binding_data();
                let state_sha=format!("{:x}",Sha256::digest(self.observed.snapshot_state_bytes()?));
                let binding=RemovalBindingData {target:descriptor.release_set_data().target_data(),source_commit:descriptor.release_set_data().current_data().binding_data().source_commit,
                    removal_descriptor_sha256:&format!("{:x}",Sha256::digest(self.source.originals.input.descriptor_data())),
                    installed_producer_sha256:&format!("{:x}",Sha256::digest(&self.source.originals.installed_raw[0])),
                    installed_inventory_sha256:descriptor.release_set_data().current_data().binding_data().inventory_sha256,
                    installation_state_sha256:&state_sha,payload_roster_sha256:&self.admission.snapshot_sha256};
                check(fields.source_commit==binding.source_commit,"removal-payload-source")?;
                let next=if slot==5 {old.first_failure_latched_data(self.first.ok_or("removal-payload-first-failure")?.1,binding)}
                    else {old.next_prefix_data(match slot {2=>PrefixData::AppWithdrawn,3=>PrefixData::PayloadRosterRemoval,
                        4=>PrefixData::PayloadAbsentObserved,_=>return Err("removal-payload-record-slot")},binding)}
                    .map_err(|_|"removal-payload-record")?;
                // Retain intended DATA before the writer can return any
                // effect. Only the actual seal/write ledger can select it as
                // a failure basis; it never grants forward phase permission.
                if slot==5 {self.failure_record=Some(next);}else{self.pending_record=Some((slot,next));}
                let retained=if slot==5{self.failure_record.as_ref()}else{self.pending_record.as_ref().map(|(_,record)|record)}
                    .ok_or("removal-payload-record")?;
                let bytes=retained.bytes_data().to_vec();let before=book.originals.len();
                check(self.remaining_originals>=3,"removal-payload-original-budget")?;
                self.snapshot.create(book,slot)?;self.snapshot.write(book,slot,&bytes)?;self.snapshot.close_file(book,slot)?;
                let used=book.originals.len().checked_sub(before).ok_or("removal-payload-original-budget")?;
                self.remaining_originals=self.remaining_originals.checked_sub(used).ok_or("removal-payload-original-budget")?;
                check(used==2 && self.snapshot.files[slot].settled_data(),"removal-payload-record-finality")?;
                maintenance::held_bytes(book,self.snapshot.files[slot].reader.ok_or("removal-payload-record")?,&bytes)?;
                let parsed=RemovalRecordData::parse_data(&bytes,binding).map_err(|_|"removal-payload-record-readback")?;
                let retained=if slot==5{self.failure_record.as_ref()}else{self.pending_record.as_ref().map(|(_,record)|record)}
                    .ok_or("removal-payload-record")?;
                check(parsed.digest_data()==retained.digest_data(),"removal-payload-record-readback")?;
                if slot!=5 {self.record=Some(self.pending_record.take().ok_or("removal-payload-record")?.1);}
                let roster=self.roster(book,self.archive())?;
                check(self.namespace_matches(self.archive(),book,&roster)?,"removal-payload-record-roster")?;
                self.external_post(book)
            }
            fn withdraw(&mut self,book:&mut Install)->Result<()> {
                check(self.phase==RemovalPayloadPhase::Transferred && self.first.is_none(),"removal-payload-withdrawal-phase")?;
                self.external_post(book)?;let app=self.current_app()?;let original=self.states[app].original.ok_or("removal-payload-current-app")?;
                let from=self.root();let to=self.archive();
                let before_from=RemovalPublication::parent_before(book,from)?;let before_to=RemovalPublication::parent_before(book,to)?;
                let from_roster=self.roster(book,from)?;let to_roster=self.roster(book,to)?;
                check(self.namespace_matches(from,book,&from_roster)? && self.namespace_matches(to,book,&to_roster)?,"removal-payload-withdrawal-roster")?;
                book.check_name(original,true)?;book.protected(original,true,Some(0o555))?;book.absent(to,"app")?;
                check(book.identity(from)?.dev==book.identity(to)?.dev && book.identity(original)?.dev==book.identity(from)?.dev,"removal-payload-withdrawal-volume")?;
                book.clock()?;
                let returned=native::publish_directory(book.fd(from)?.as_fd(),paths::APP_NAME,book.fd(to)?.as_fd(),"app");
                self.withdrawal_return=Some(match &returned {Ok(())=>Ok(()),Err(error)=>Err(error.raw_os_error())});
                if let Err(error)=returned {
                    if error.raw_os_error()!=Some(Errno::EEXIST as i32){book.unknown=true;self.states[app].effect=RemovalNodeEffect::Unknown;}
                    return Err("removal-payload-exclusive-withdrawal");
                }
                // Known returned rename precedes the next clock/POST.
                self.phase=RemovalPayloadPhase::AppWithdrawn;book.clock()?;
                maintenance::rebind_removal_app(book,original,to)?;
                self.plan.nodes[app].name="app".to_owned();self.plan.nodes[app].identity=book.identity(original)?;
                book.absent(from,paths::APP_NAME)?;
                self.advance_parent(book,from,before_from)?;self.advance_parent(book,to,before_to)?;
                book.persist(from,false)?;book.persist(to,false)?;
                self.progress(book,2)?;
                // Phase ENTRY, durably observed before any irreversible unlink.
                self.progress(book,3)?;self.phase=RemovalPayloadPhase::Removing;Ok(())
            }
            fn node_original(&mut self,book:&mut Install,index:usize,parent:usize)->Result<usize> {
                check(self.states[index].effect==RemovalNodeEffect::Present,"removal-payload-node-state")?;
                let n=if let Some(n)=self.states[index].original {n}else {
                    let name=self.plan.nodes[index].name.clone();let directory=self.plan.nodes[index].directory;
                    let n=self.original_open(book,Some(parent),&name,directory)?;self.states[index].original=Some(n);n
                };
                let node=&self.plan.nodes[index];let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-payload-node-stat")?;
                check(book.originals[n].parent==Some(parent) && book.originals[n].name==node.name
                    && Identity::of(&actual)==node.identity && actual.st_flags==node.flags && node.flags==0,"removal-payload-node-original")?;
                book.protected(n,node.directory,Some(if node.directory||node.executable{0o555}else{0o444}))?;
                native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-payload-node-attributes")?;book.check_name(n,true)?;Ok(n)
            }
            fn remove_node(&mut self,book:&mut Install,index:usize,parent:usize,keep_root:bool,depth:usize)->Result<()> {
                check(depth<=17 && (!self.plan.nodes[index].directory || depth<17)
                    && removal_payload_phase_allows_unlink_data(self.phase,self.snapshot.files[3].settled_data(),self.first.is_some()),
                    "removal-payload-unlink-phase")?;
                self.external_post(book)?;book.check_name(parent,true)?;
                let n=self.node_original(book,index,parent)?;
                if self.plan.nodes[index].directory {
                    let roster=self.roster(book,n)?;check(self.remaining_children(index,&roster),"removal-payload-directory-roster")?;
                    self.states[index].roster_observed=true;
                    for child_position in 0..self.plan.nodes[index].children.len() {
                        let child=self.plan.nodes[index].children[child_position];
                        self.remove_node(book,child,n,false,depth+1)?;
                    }
                    // Last-child POST (or the initial empty reader) was actual.
                    // Unchanged full metadata proves that exact empty census
                    // remains current; no offset rewind or unbudgeted reader.
                    book.check_name(n,true)?;
                    check(self.states[index].roster_observed && self.plan.nodes[index].children.iter()
                        .all(|c|self.states[*c].effect==RemovalNodeEffect::Removed),"removal-payload-directory-not-empty")?;
                    book.persist(n,false)?;
                    if keep_root{return Ok(());}
                } else {
                    let node=&self.plan.nodes[index];let digest=book.read(n,node.size,false)?.0;
                    check(removal_hex_data::<32>(&digest)?==node.digest,"removal-payload-node-content")?;
                    book.check_name(n,true)?;
                }
                self.unlink_original(book,index,parent,n)
            }
            fn unlink_original(&mut self,book:&mut Install,index:usize,parent:usize,n:usize)->Result<()> {
                check(removal_payload_phase_allows_unlink_data(self.phase,self.snapshot.files[3].settled_data(),self.first.is_some())
                    && self.states[index].effect==RemovalNodeEffect::Present,"removal-payload-unlink-phase")?;
                let current_app=self.current_app()?;
                check(removal_payload_app_last_data(index,current_app,&self.states),"removal-payload-app-directory-last")?;
                self.external_post(book)?;book.check_name(n,true)?;
                let before=RemovalPublication::parent_before(book,parent)?;
                let node=&self.plan.nodes[index];let name=node.name.clone();let directory=node.directory;
                check(book.originals[n].parent==Some(parent) && book.originals[n].name==name,"removal-payload-unlink-original")?;
                let before_child=stat::fstat(book.fd(n)?).map_err(|_|"removal-payload-unlink-stat")?;
                check(Identity::of(&before_child)==node.identity && before_child.st_flags==node.flags,"removal-payload-unlink-original")?;
                book.clock()?;
                let returned=unistd::unlinkat(book.fd(parent)?,name.as_str(),if directory{unistd::UnlinkatFlags::RemoveDir}else{unistd::UnlinkatFlags::NoRemoveDir});
                match returned {
                    Ok(())=>{self.states[index].returned=Some(Ok(()));self.states[index].effect=RemovalNodeEffect::Removed;},
                    Err(error)=>{self.states[index].returned=Some(Err(error as i32));self.states[index].effect=RemovalNodeEffect::Unknown;
                        book.unknown=true;return Err("removal-payload-unlink-return");}
                }
                // Keep the actual effect before the next deadline/POST. This
                // original no longer has a name; generic named POST is invalid.
                book.clock()?;book.absent(parent,&name)?;
                let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-payload-unlinked-stat")?;
                check(node.identity.dev==i64::from(actual.st_dev) && node.identity.ino==actual.st_ino
                    && node.identity.mode==u32::from(actual.st_mode) && node.identity.uid==actual.st_uid
                    && node.identity.gid==actual.st_gid && actual.st_flags==0,"removal-payload-unlinked-original")?;
                self.advance_parent(book,parent,before)?;
                book.forward_close(n,"removal-payload-unlinked-close")?;
                if directory {book.persist(parent,false)?;}
                self.external_post(book)
            }
            fn final_namespace(&mut self,book:&mut Install)->Result<()> {
                check(self.withdrawal_return==Some(Ok(())) && self.states.iter().all(|s|s.effect==RemovalNodeEffect::Removed
                    && s.returned==Some(Ok(())) && s.original.is_some_and(|n|book.originals[n].state==State::Closed && book.originals[n].fd.is_none())),
                    "removal-payload-original-finality")?;
                self.external_post(book)?;
                book.absent(self.root(),paths::APP_NAME)?;book.absent(self.archive(),"app")?;
                for g in 0..self.plan.generations.len() {
                    if g>0 {book.absent(self.root(),&self.plan.generations[g].app_name)?;}
                }
                // Complete retained control namespace, not just payload names.
                for row in self.snapshot.capture.directory_rows_data() {
                    let path=row.0;
                    let (parent,name)=if path.is_empty(){
                        let root=&book.originals[self.root()];(root.parent,root.name.clone())
                    }else if let Some(("versions",leaf))=path.split_once('/') {
                        (Some(self.snapshot.capture.versions_original()?),leaf.to_owned())
                    }else{(Some(self.root()),path.to_owned())};
                    // The ordinary capture only has root/versions/release/stage
                    // directories; no payload node/path is admitted here.
                    check(!path.contains('/') || path.starts_with("versions/")&&!path[9..].contains('/'),"removal-payload-control-location")?;
                    check(self.remaining_originals>=2,"removal-payload-original-budget")?;
                    self.remaining_originals-=2;
                    let reader=book.open(parent,&name,true)?;
                    let live=if path.is_empty(){self.root()}else if path=="versions"{self.snapshot.capture.versions_original()?}
                        else if let Some((g,_))=self.plan.generations.iter().enumerate().find(|(_,g)|path==format!("versions/{}",g.release)){self.release_originals[g]}
                        else{reader};
                    let expected=if live==reader{row.1}else{book.identity(live)?};
                    check(book.identity(reader)?==expected && stat::fstat(book.fd(reader)?).map_err(|_|"removal-payload-control-stat")?.st_flags==row.2,
                        "removal-payload-control-original")?;
                    book.protected(reader,true,Some(if path.starts_with(".install-"){0o700}else{0o755}))?;
                    native::no_xattrs(book.fd(reader)?.as_fd()).map_err(|_|"removal-payload-control-attributes")?;
                    let original=&book.originals[reader];let grandparent=original.parent;let label=original.name.clone();
                    let roster_reader=book.open(grandparent,&label,true)?;
                    check(book.identity(roster_reader)?==book.identity(reader)?,"removal-payload-control-roster-original")?;
                    let actual=book.roster(roster_reader)?;
                    let matches=if path.is_empty(){self.namespace_matches(self.root(),book,&actual)?}
                        else if let Some((g,_))=self.plan.generations.iter().enumerate().find(|(_,g)|path==format!("versions/{}",g.release)) {
                            self.namespace_matches(self.release_originals[g],book,&actual)?
                        }else{actual.len()==row.3.len() && row.3.iter().all(|(n,i)|actual.get(n)==Some(i))};
                    check(matches,"removal-payload-control-roster")?;
                    book.check_name(roster_reader,true)?;book.forward_close(roster_reader,"removal-payload-control-roster-close")?;
                    book.check_name(reader,true)?;book.forward_close(reader,"removal-payload-control-close")?;
                }
                let before=book.originals.len();
                let prior=self.snapshot.capture.prior_archives()?;
                let quoted=prior.rows().len().checked_mul(8).ok_or("removal-payload-original-budget")?;
                check(self.remaining_originals>=quoted,"removal-payload-original-budget")?;
                maintenance::post_removal_archive_after_snapshot(book,prior)?;
                let used=book.originals.len().checked_sub(before).ok_or("removal-payload-original-budget")?;
                check(used<=quoted,"removal-payload-original-budget")?;self.remaining_originals-=used;
                self.snapshot.file_post(book,0)?;self.snapshot.file_post(book,1)?;
                for slot in 2..4 {self.snapshot.file_post(book,slot)?;}
                self.external_post(book)
            }
            fn run_inner(&mut self,book:&mut Install)->Result<RemovalPayloadAbsence> {
                self.transfer(book)?;self.withdraw(book)?;
                let current_app=self.current_app()?;
                self.remove_node(book,current_app,self.archive(),true,0)?;
                for g in 0..self.plan.generations.len() {
                    // At most ONE new generation anchor remains live. Its
                    // identity stays in the original ledger after known close;
                    // the final 2C census uses independently owned readers.
                    let name=self.plan.generations[g].release.clone();
                    let release=self.original_open(book,Some(self.snapshot.capture.versions_original()?),&name,true)?;
                    let (identity,flags)=self.snapshot.capture.directory_identity(&format!("versions/{name}"))?;
                    check(book.identity(release)?==identity && flags==0,"removal-payload-release-original")?;
                    book.protected(release,true,Some(0o755))?;self.release_originals.push(release);
                    if g>0 {let app=self.plan.generations[g].roots[0].ok_or("removal-payload-app-root")?;self.remove_node(book,app,self.root(),false,0)?;}
                    let runtime=self.plan.generations[g].roots[1].ok_or("removal-payload-runtime-root")?;
                    self.remove_node(book,runtime,release,false,0)?;
                    book.check_name(release,true)?;book.forward_close(release,"removal-payload-release-close")?;
                }
                let app_original=self.states[current_app].original.ok_or("removal-payload-current-app")?;
                self.unlink_original(book,current_app,self.archive(),app_original)?;
                self.final_namespace(book)?;
                self.progress(book,4)?;self.phase=RemovalPayloadPhase::Absent;
                self.snapshot.file_post(book,4)?;
                let record=self.snapshot.files[4].reader.ok_or("removal-payload-record")?;
                Ok(RemovalPayloadAbsence {archive:self.archive(),snapshot:self.admission.snapshot,record,
                    record_sha256:self.record.as_ref().ok_or("removal-payload-record")?.digest_data().to_owned()})
            }
            fn run(&mut self,book:&mut Install)->Result<RemovalPayloadAbsence> {
                let result=self.run_inner(book);
                if let Err(error)=result {
                    use mobile_release_desktop::macos_remove_record::FailureKindData;
                    self.note(error,if error.contains("close"){FailureKindData::CloseUnknown}
                        else if book.unknown{FailureKindData::OriginalUnknown}
                        else if error.contains("persist"){FailureKindData::Persistence}
                        else if book.clock().is_err(){FailureKindData::Deadline}
                        else if error=="removal-payload-exclusive-withdrawal"{FailureKindData::OriginalFailed}
                        else{FailureKindData::PostMismatch});
                    // Actual failure persists in memory even if no further work
                    // can be safely admitted. Never retry a partial failure file.
                    if self.phase!=RemovalPayloadPhase::OriginalSource && !book.unknown && book.clock().is_ok()
                        && self.record.is_some() && self.failure_record.is_none() && self.snapshot.files[5].writer.is_none() {
                        let _=self.progress(book,5);
                    }
                }result
            }
        }

        // Recovery is an actual executing SOURCE/current-original admission,
        // not a deserialized live RemovalAdmission or synthetic peer completion.
        // This private adapter remains unreachable from either entry form.
        const REMOVAL_RESUME_RAW:usize=1024*1024;
        fn removal_resume_target()->mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData {
            if cfg!(target_arch="aarch64"){mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Arm64}
            else{mobile_release_desktop::macos_install_maintenance::MaintenanceTargetData::Intel}
        }
        fn removal_resume_path_data(path:&str)->bool {
            path.len()>1 && path.len()<1024 && path.starts_with('/') && path.is_ascii()
                && !path.as_bytes().contains(&0) && path[1..].split('/').count()<=32
                && path[1..].split('/').all(|p|!p.is_empty() && p.len()<=255 && p!="." && p!="..")
                && path.rsplit('/').next()==Some("mrk-macos-remove")
        }
        fn removal_resume_stat(book:&Install,n:usize,directory:bool,mode:Option<u32>)->Result<()> {
            book.clock()?;book.check_name(n,true)?;book.protected(n,directory,mode)?;book.clock()?;
            native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"removal-resume-attributes")?;book.clock()?;
            let actual=stat::fstat(book.fd(n)?).map_err(|_|"removal-resume-stat")?;
            check(actual.st_flags==0 && Identity::of(&actual)==book.identity(n)?,"removal-resume-original")?;
            book.check_name(n,true)
        }
        fn removal_resume_read_at(book:&Install,n:usize,offset:u64,buf:&mut[u8])->Result<usize> {
            book.clock()?;let at=i64::try_from(offset).map_err(|_|"removal-resume-offset")?;
            let count=nix::sys::uio::pread(book.fd(n)?,buf,at).map_err(|_|"removal-resume-read")?;
            check(count<=buf.len(),"removal-resume-read-count")?;book.clock()?;Ok(count)
        }
        fn removal_resume_hash(book:&Install,n:usize,limit:u64)->Result<[u8;32]> {
            book.check_name(n,true)?;let size=u64::try_from(book.identity(n)?.size).map_err(|_|"removal-resume-size")?;
            check(size>0 && size<=limit,"removal-resume-size")?;
            let mut block=[0u8;65536];let mut digest=Sha256::new();let mut at=0;
            while at<size {let amount=(size-at).min(block.len() as u64) as usize;
                let count=removal_resume_read_at(book,n,at,&mut block[..amount])?;
                check(count>0,"removal-resume-eof")?;digest.update(&block[..count]);at+=count as u64;}
            check(removal_resume_read_at(book,n,size,&mut block[..1])?==0,"removal-resume-eof")?;
            book.check_name(n,true)?;Ok(digest.finalize().into())
        }
        fn removal_resume_span(book:&Install,n:usize,span:&maintenance::RemovalControlSpanData,limit:usize)->Result<Vec<u8>> {
            let size=usize::try_from(span.len_data()).map_err(|_|"removal-resume-span-size")?;
            let total=u64::try_from(book.identity(n)?.size).map_err(|_|"removal-resume-size")?;
            check(size>0 && size<=limit && limit<=installation_record::INVENTORY_LIMIT
                && span.offset_data().checked_add(span.len_data()).is_some_and(|end|end<=total),"removal-resume-span-size")?;
            let mut raw=Vec::new();raw.try_reserve_exact(size).map_err(|_|"removal-resume-allocation")?;
            check(raw.capacity()<=size,"removal-resume-allocation")?;raw.resize(size,0);
            let mut at=0;while at<size {
                let count=removal_resume_read_at(book,n,span.offset_data()+at as u64,&mut raw[at..])?;
                check(count>0,"removal-resume-span-eof")?;at+=count;
            }
            check(<[u8;32]>::from(Sha256::digest(&raw))==*span.digest_data(),"removal-resume-span-hash")?;
            book.check_name(n,true)?;Ok(raw)
        }
        struct RemovalResumeGenesis {
            archive:usize,snapshot:usize,tip_archive:usize,tip_original:usize,
            data:maintenance::RemovalGenesisData,tip_raw:Vec<u8>,
            // Whole genesis bytes are never materialized. Only these four
            // actual signature operands are retained, inside the prior quote.
            raw:[Vec<u8>;4],census:maintenance::RemovalArchiveCensus,
            genesis_index:usize,tip_index:usize,
        }
        impl RemovalResumeGenesis {
            fn span<'a>(data:&'a maintenance::RemovalGenesisData,kind:u8,path:&str)->Result<&'a maintenance::RemovalControlSpanData> {
                let mut rows=data.controls_data().iter().filter(|r|r.kind_data()==kind && r.path_data()==path);
                let row=rows.next().ok_or("removal-resume-control-span")?;
                check(rows.next().is_none(),"removal-resume-control-span")?;Ok(row)
            }
            fn post(&self,book:&Install)->Result<()> {
                let genesis=&self.census.rows()[self.genesis_index];let tip=&self.census.rows()[self.tip_index];
                for (n,row) in [(self.archive,genesis),(self.tip_archive,tip)] {
                    removal_resume_stat(book,n,true,Some(0o700))?;
                    check(book.identity(n)?==row.identity(),"removal-resume-archive-original")?;
                }
                for (n,file) in [(self.snapshot,genesis.files()[0].as_ref()),
                    (self.tip_original,tip.files()[tip.attempt_data().ok_or("removal-resume-tip")?.tip_slot_data()].as_ref())] {
                    let file=file.ok_or("removal-resume-history-file")?;
                    removal_resume_stat(book,n,false,Some(0o444))?;
                    check(book.identity(n)?==file.identity() && file.shape_tag_data()==2,"removal-resume-history-original")?;
                }
                maintenance::held_bytes(book,self.tip_original,&self.tip_raw)?;
                check(*self.data.whole_sha256_data()==*genesis.files()[0].as_ref().ok_or("removal-resume-snapshot")?.digest(),
                    "removal-resume-genesis-hash")?;book.clock()
            }
            fn content_post(&self,book:&Install)->Result<()> {
                self.post(book)?;
                check(removal_resume_hash(book,self.snapshot,maintenance::REMOVAL_SNAPSHOT_LIMIT)?==*self.data.whole_sha256_data(),
                    "removal-resume-genesis-hash")?;self.post(book)
            }
        }
        struct RemovalResumeOriginals {
            input:completed_package::Input,bootstrap:Vec<usize>,executed:String,parent_path:String,
            program:usize,script:usize,program_sha:[u8;32],root:usize,root_chain:Vec<usize>,
            installed_pair:[usize;2],installed_raw:[Vec<u8>;2],genesis:Option<RemovalResumeGenesis>,
        }
        impl RemovalResumeOriginals {
            fn memory(&self)->Result<()> {
                let mut raw=self.input.retained_bytes_data()?.checked_add(self.bootstrap.capacity()*std::mem::size_of::<usize>())
                    .and_then(|n|n.checked_add(self.root_chain.capacity()*std::mem::size_of::<usize>()))
                    .and_then(|n|n.checked_add(self.executed.capacity()+self.parent_path.capacity()))
                    .ok_or("removal-resume-memory")?;
                for bytes in &self.installed_raw {raw=raw.checked_add(bytes.capacity()).ok_or("removal-resume-memory")?;}
                if let Some(genesis)=&self.genesis {
                    raw=raw.checked_add(genesis.data.owned_bytes_data()?).and_then(|n|n.checked_add(genesis.tip_raw.capacity()))
                        .ok_or("removal-resume-memory")?;
                    for bytes in &genesis.raw{raw=raw.checked_add(bytes.capacity()).ok_or("removal-resume-memory")?;}
                    check(genesis.census.owned_bytes()?<=128*1024,"removal-resume-census-memory")?;
                }
                // Census + parser live in the existing once-reserved2MiB.
                // Typed bounded release/policy objects + stack working blocks
                // are separately covered by the reserved512KiB allowance.
                check(raw<=REMOVAL_RESUME_RAW,"removal-resume-memory")
            }
            fn post(&self,book:&Install)->Result<()> {
                self.memory()?;
                self.input.post(book)?;
                check(std::env::current_exe().ok().as_deref()==Some(Path::new(&self.executed)),"removal-resume-executed-image")?;
                for n in self.bootstrap.iter().chain(&self.root_chain) {book.check_name(*n,true)?;}
                removal_resume_stat(book,self.program,false,Some(0o555))?;
                maintenance::held_bytes(book,self.script,include_bytes!("../../../macos-installed-inputs/remove-postinstall"))?;
                for (n,raw) in self.installed_pair.iter().zip(&self.installed_raw){maintenance::held_bytes(book,*n,raw)?;}
                if let Some(genesis)=&self.genesis{genesis.post(book)?;}
                book.clock()
            }
            fn fixed_absence(&self,book:&Install)->Result<()> {
                self.post(book)?;removal_resume_stat(book,self.root,true,Some(0o755))?;
                book.absent(self.root,paths::APP_NAME)?;book.check_name(self.root,true)
            }
        }
        fn removal_resume_point(book:&Install,originals:&RemovalResumeOriginals,first:&mut Option<&'static str>,
            point:native::install_producer::ProducerCheckpoint)->native::android_service_management::Decision {
            use native::android_service_management::Decision;
            let (phase,custody)=producer_phase(point);
            if phase.is_cleanup(){return producer_cleanup_point(book,point);}
            if custody.unknown{first.get_or_insert("removal-resume-native-unknown");return Decision::Unknown;}
            if first.is_some(){return Decision::Stop;}
            if let Err(error)=originals.post(book){first.get_or_insert(error);
                return if book.shared_deadline().is_ok_and(Deadline::is_unknown){Decision::Unknown}else{Decision::Stop};}
            Decision::Proceed
        }
        pub(super) struct RemovalResumeSource {
            originals:RemovalResumeOriginals,
            program:native::install_producer::RemovalRecoveryProgramVerifier,
            remove:native::install_producer::RemovalProducerVerifier,
            installed:native::install_producer::ProducerVerifier,
            self_verified:bool,verified:bool,first:Option<&'static str>,existing_maintenance:Option<usize>,
            descriptor:mobile_release_desktop::macos_install_producer::ProducerData,
            removal:mobile_release_desktop::macos_remove_producer::RemovalData,
        }
        impl RemovalResumeSource {
            fn new(book:&mut Install,completed:&str)->Result<Self> {
                use native::install_producer::{RemovalRecoveryProgramVerifier,RemovalProducerVerifier,ProducerVerifier};
                check(cfg!(feature="macos-installed-remover") && !cfg!(feature="macos-installed-installer-fixture")
                    && unistd::getuid().is_root() && unistd::geteuid().is_root() && unistd::getgid().as_raw()==0
                    && unistd::getegid().as_raw()==0,"removal-resume-fixed-role")?;
                book.clock()?;native::platform().map_err(|_|"removal-resume-platform")?;book.clock()?;
                check(book.removal_control_reserved==0 && book.removal_live_reserved==0
                    && !book.registration.entered && !book.gate.entered,"removal-resume-once")?;
                let bound=RemovalRecoveryProgramVerifier::project_owned_upper_bound()
                    .and_then(|n|n.checked_add(RemovalProducerVerifier::project_owned_upper_bound()?))
                    .and_then(|n|n.checked_add(ProducerVerifier::project_owned_upper_bound()?))
                    .and_then(|n|n.checked_add(REMOVAL_RESUME_RAW+512*1024+std::mem::size_of::<Self>()))
                    .filter(|n|*n<=16*1024*1024).ok_or("removal-resume-resource")?;
                book.removal_control_reserved=bound as u64;
                let path=std::env::current_exe().map_err(|_|"removal-resume-executed-image")?;
                let executed=path.to_str().filter(|s|removal_resume_path_data(s)).ok_or("removal-resume-executed-image")?.to_owned();
                let parent_path=executed.rsplit_once('/').ok_or("removal-resume-executed-image")?.0.to_owned();
                check(!parent_path.is_empty(),"removal-resume-executed-image")?;
                let mut bootstrap=Vec::new();bootstrap.try_reserve_exact(32).map_err(|_|"removal-resume-allocation")?;
                let mut parent=book.open(None,"/",true)?;book.protected_as(parent,true,None,AclRole::SystemRoot)?;bootstrap.push(parent);
                for part in parent_path[1..].split('/') {
                    parent=book.open(Some(parent),part,true)?;book.protected(parent,true,None)?;book.check_name(parent,true)?;
                    check(bootstrap.len()<32,"removal-resume-path-bound")?;bootstrap.push(parent);
                }
                removal_resume_stat(book,parent,true,None)?;
                check(book.identity(parent)?.gid==0,"removal-resume-parent-group")?;
                let roster=maintenance::roster_now(book,parent)?;
                check(roster.keys().map(String::as_str).eq(["mrk-macos-remove","postinstall"]),"removal-resume-script-roster")?;
                let program=book.open(Some(parent),"mrk-macos-remove",false)?;
                removal_resume_stat(book,program,false,Some(0o555))?;
                let script=book.open(Some(parent),"postinstall",false)?;removal_resume_stat(book,script,false,Some(0o555))?;
                maintenance::held_bytes(book,script,include_bytes!("../../../macos-installed-inputs/remove-postinstall"))?;
                let program_sha=removal_resume_hash(book,program,64*1024*1024)?;
                let input=completed_package::Input::open_removal(book,completed)?;
                let support=book.support_root()?;let root=book.open(Some(support),"MobileReleaseKit",true)?;
                removal_resume_stat(book,root,true,Some(0o755))?;book.absent(root,paths::APP_NAME)?;
                let mut root_chain=Vec::new();let mut at=Some(root);
                while let Some(n)=at{check(root_chain.len()<4,"removal-resume-root-chain")?;root_chain.push(n);at=book.originals[n].parent;}
                let names=mobile_release_desktop::macos_install_producer::installed_control_names_data(removal_resume_target(),paths::RELEASE)
                    .map_err(|_|"removal-resume-control-name")?;
                let (descriptor_original,raw)=maintenance::metadata_original(book,root,&names.0,mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT)?;
                let (signature_original,sig)=maintenance::metadata_original(book,root,&names.1,mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT)?;
                // Only a bounded comparison prelude. These parser results
                // select no effects or payload roots until native3 completes.
                let removal=mobile_release_desktop::macos_remove_producer::RemovalData::parse_data(input.descriptor_data(),removal_resume_target())
                    .map_err(|_|"removal-resume-remove-data")?;
                let descriptor=removal.installed_data(&raw).map_err(|_|"removal-resume-installed-data")?;
                let binding=descriptor.release_set_data().current_data().binding_data();
                check(removal_source_binding_data(&binding,option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"),
                    option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),removal.binding_data().package_sha256,input.package_sha256_data()),
                    "removal-resume-source-data")?;
                check(removal_hex_data::<32>(removal.binding_data().remover_executable_sha256)?==program_sha,"removal-resume-program-hash")?;
                let originals=RemovalResumeOriginals{input,bootstrap,executed,parent_path,program,script,program_sha,root,root_chain,
                    installed_pair:[descriptor_original,signature_original],installed_raw:[raw,sig],genesis:None};
                originals.fixed_absence(book)?;
                check(book.originals.iter().filter(|n|n.fd.is_some()).count().checked_add(32+EXTRA_LIVE)
                    .is_some_and(|n|n<=96),"removal-resume-source-live-reservation")?;
                Ok(Self {originals,program:RemovalRecoveryProgramVerifier::new(),remove:RemovalProducerVerifier::new(),
                    installed:ProducerVerifier::new(),self_verified:false,verified:false,first:None,existing_maintenance:None,descriptor,removal})
            }
            fn inspect_self(&mut self,book:&Install)->Result<()> {
                check(!self.self_verified && !self.program.custody().entered,"removal-resume-self-once")?;
                let result={let Self{originals,program,first,..}=self;
                    let directory=*originals.bootstrap.last().ok_or("removal-resume-parent")?;
                    program.verify_and_close(book.fd(directory)?.as_fd(),book.fd(originals.program)?.as_fd(),Path::new(&originals.parent_path),
                        &mut |point|removal_resume_point(book,originals,first,point))};
                check(result==native::install_producer::RemovalRecoveryProgramResult::ExecutingSourceVerified && self.program.settled(),
                    self.first.unwrap_or("removal-resume-self-refused"))?;
                self.self_verified=true;self.originals.fixed_absence(book)
            }
            fn reserve_existing(&mut self,book:&mut Install)->Result<()> {
                check(self.self_verified && self.program.settled() && self.first.is_none(),"removal-resume-self-required")?;
                self.originals.fixed_absence(book)?;
                // Explicitly require the existing name before the ordinary R
                // original helper: its fresh-install creation branch is never used.
                check(book.named(Some(self.root_original()),paths::REGISTRATION_GATE_NAME).is_ok(),"removal-resume-existing-r")?;
                book.registration_before_maintenance(self.root_original())?;self.reservation_post(book)?;
                check(self.existing_maintenance.is_none() && book.gate.parent.is_none() && book.gate.participant.is_none(),
                    "removal-resume-existing-m-once")?;
                book.gate.parent=Some(self.root_original());book.gate.creation="existing-not-modified";
                let n=book.open_role(Some(self.root_original()),paths::MAINTENANCE_GATE_NAME,false,Role::GateParticipant)?;
                self.existing_maintenance=Some(n);
                book.gate_protected(n)?;maintenance::held_bytes(book,n,paths::MAINTENANCE_GATE_BYTES)?;book.gate.verified=true;
                self.existing_maintenance_post(book)
            }
            pub(super) fn root_original(&self)->usize {self.originals.root}
            pub(super) fn prelude_selection_data(&self,book:&Install)->Result<&ReleaseSetData> {
                self.reservation_post(book)?;Ok(self.descriptor.release_set_data())
            }
            fn reservation_post(&self,book:&Install)->Result<()> {
                check(self.self_verified && self.program.settled() && self.first.is_none()
                    && !book.worker_stderr_is_gate && book.registration.entered && book.registration.verified
                    && book.registration.parent==Some(self.root_original()) && book.registration.creation=="existing-not-modified"
                    && book.registration.lock_attempted && book.registration.exclusive_acquired && !book.registration.closed_under_maintenance,
                    "removal-resume-r-original")?;
                book.registration_protected(book.registration.participant.ok_or("removal-resume-r-original")?)?;
                self.originals.fixed_absence(book)
            }
            fn existing_maintenance_post(&self,book:&Install)->Result<()> {
                self.reservation_post(book)?;
                let n=self.existing_maintenance.ok_or("removal-resume-m-original")?;
                check(book.gate.parent==Some(self.root_original()) && book.gate.participant==Some(n) && book.gate.verified
                    && book.gate.creation=="existing-not-modified" && book.gate.writer.is_none()
                    && book.originals[n].state==State::Owned && book.originals[n].role==Role::GateParticipant
                    && book.originals[n].parent==Some(self.root_original()) && book.originals[n].name==paths::MAINTENANCE_GATE_NAME,
                    "removal-resume-m-original")?;
                let flags=fcntl::fcntl(book.fd(n)?,fcntl::FcntlArg::F_GETFL).map_err(|_|"removal-resume-m-flags")?;
                check(flags&OFlag::O_ACCMODE.bits()==OFlag::O_RDONLY.bits(),"removal-resume-m-readonly")?;
                book.gate_protected(n)?;maintenance::held_bytes(book,n,paths::MAINTENANCE_GATE_BYTES)
            }
            fn native_settled(&self)->bool {self.program.settled()&&self.remove.settled()&&self.installed.settled()}
            fn settle(&mut self,book:&Install)->bool {
                let mut gate=|point|producer_cleanup_point(book,point);
                let installed=self.installed.close(&mut gate);let remove=self.remove.close(&mut gate);let program=self.program.close(&mut gate);
                installed&&remove&&program&&self.native_settled()
            }
        }
        impl RemovalResumeSource {
            fn load_genesis(&mut self,book:&mut Install,census:maintenance::RemovalArchiveCensus,state_sha:[u8;32])->Result<()> {
                self.existing_maintenance_post(book)?;
                check(self.originals.genesis.is_none() && !self.verified && !book.gate.entered
                    && !book.gate.lock_attempted && !book.gate.exclusive_acquired,"removal-resume-genesis-once")?;
                let current=self.removal.binding_data();let expected=[
                    <[u8;32]>::from(Sha256::digest(self.originals.input.descriptor_data())),
                    <[u8;32]>::from(Sha256::digest(&self.originals.installed_raw[0])),
                    removal_hex_data::<32>(current.installed_inventory_sha256)?,state_sha];
                let source=removal_hex_data::<20>(current.source_commit)?;
                let mut selected=None;
                for (index,row) in census.rows().iter().enumerate() {
                    if !census.is_tip_data(index){continue;}
                    let Some(attempt)=row.attempt_data() else{continue;};let binding=attempt.binding_data();
                    if binding.target_data()==removal_resume_target() && binding.source_data()==&source
                        && binding.digests_data()[..4]==expected {
                        check(selected.is_none(),"removal-resume-ambiguous-tip")?;selected=Some(index);
                    }
                }
                let tip_index=selected.ok_or("removal-resume-genesis-missing")?;
                let genesis_index=census.genesis_index_data(tip_index).ok_or("removal-resume-genesis-missing")?;
                let row=&census.rows()[genesis_index];
                check(removal_archive_name_data(row.name()),"removal-resume-genesis-name")?;
                let archive=book.open(Some(self.root_original()),row.name(),true)?;
                removal_resume_stat(book,archive,true,Some(0o700))?;
                check(book.identity(archive)?==row.identity(),"removal-resume-genesis-directory")?;
                let file=row.files()[0].as_ref().ok_or("removal-resume-genesis-file")?;
                check(file.shape_tag_data()==2,"removal-resume-genesis-unsealed")?;
                let snapshot=book.open(Some(archive),"snapshot-v2",false)?;
                removal_resume_stat(book,snapshot,false,Some(0o444))?;
                check(book.identity(snapshot)?==file.identity(),"removal-resume-genesis-file")?;
                let data=maintenance::parse_removal_genesis_data(file.len(),&row.name()[8..],
                    |at,buf|removal_resume_read_at(book,snapshot,at,buf))?;
                check(data.whole_sha256_data()==file.digest() && data.binding_data()?==*census.rows()[tip_index].attempt_data()
                    .ok_or("removal-resume-tip")?.binding_data(),"removal-resume-genesis-binding")?;
                check(data.selected_bytes_data()==self.descriptor.release_set_data().encode_data().map_err(|_|"removal-resume-selected")?,
                    "removal-resume-selected")?;
                let names=mobile_release_desktop::macos_install_producer::installed_control_names_data(removal_resume_target(),paths::RELEASE)
                    .map_err(|_|"removal-resume-control-name")?;
                let raw=[
                    removal_resume_span(book,snapshot,RemovalResumeGenesis::span(&data,1,"@remove/producer.json")?,
                        mobile_release_desktop::macos_remove_producer::DESCRIPTOR_LIMIT)?,
                    removal_resume_span(book,snapshot,RemovalResumeGenesis::span(&data,2,"@remove/producer.sig")?,512)?,
                    removal_resume_span(book,snapshot,RemovalResumeGenesis::span(&data,0,&names.0)?,
                        mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT)?,
                    removal_resume_span(book,snapshot,RemovalResumeGenesis::span(&data,0,&names.1)?,
                        mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT)?,
                ];
                check(raw[0]==self.originals.input.descriptor_data() && raw[1]==self.originals.input.signature_data()
                    && raw[2]==self.originals.installed_raw[0] && raw[3]==self.originals.installed_raw[1],
                    "removal-resume-same-artifact-required")?;
                let tip=&census.rows()[tip_index];let attempt=tip.attempt_data().ok_or("removal-resume-tip")?;
                let tip_archive=if tip_index==genesis_index{archive}else{
                    check(removal_archive_name_data(tip.name()),"removal-resume-tip-name")?;
                    let n=book.open(Some(self.root_original()),tip.name(),true)?;
                    removal_resume_stat(book,n,true,Some(0o700))?;
                    check(book.identity(n)?==tip.identity(),"removal-resume-tip-directory")?;n};
                let tip_file=tip.files()[attempt.tip_slot_data()].as_ref().ok_or("removal-resume-tip-file")?;
                let tip_original=book.open(Some(tip_archive),removal_payload_file_name(attempt.tip_slot_data())?,false)?;
                removal_resume_stat(book,tip_original,false,Some(0o444))?;
                check(book.identity(tip_original)?==tip_file.identity() && tip_file.digest()==attempt.raw_tip_sha256_data(),
                    "removal-resume-tip-file")?;
                check(tip_file.len()>0 && tip_file.len()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64,"removal-resume-tip-size")?;
                let (_,tip_raw)=book.read(tip_original,tip_file.len(),true)?;
                check(tip_raw.len()<=mobile_release_desktop::macos_remove_record::RECORD_LIMIT
                    && <[u8;32]>::from(Sha256::digest(&tip_raw))==*attempt.raw_tip_sha256_data(),"removal-resume-tip-hash")?;
                check(raw.iter().try_fold(data.owned_bytes_data()?,|n,b|n.checked_add(b.capacity()).ok_or("removal-resume-memory"))?
                    .checked_add(tip_raw.capacity()).is_some_and(|n|n<=REMOVAL_RESUME_RAW),"removal-resume-memory")?;
                self.originals.genesis=Some(RemovalResumeGenesis{archive,snapshot,tip_archive,tip_original,data,tip_raw,raw,
                    census,genesis_index,tip_index});
                self.originals.post(book)
            }
            fn inspect_signed_genesis(&mut self,book:&Install)->Result<()> {
                use native::install_producer::SignatureResult;
                check(self.self_verified && !self.verified && !self.remove.custody().entered && !self.installed.custody().entered,
                    "removal-resume-signatures-once")?;
                self.existing_maintenance_post(book)?;self.originals.genesis.as_ref().ok_or("removal-resume-genesis")?.content_post(book)?;
                let removed={let Self{originals,remove,first,..}=self;
                    let genesis=originals.genesis.as_ref().ok_or("removal-resume-genesis")?;
                    remove.verify_and_close(&genesis.raw[0],&genesis.raw[1],
                        &mut |point|removal_resume_point(book,originals,first,point))};
                check(removed==SignatureResult::SignatureVerified && self.remove.settled(),
                    self.first.unwrap_or("removal-resume-remove-signature"))?;
                let installed={let Self{originals,installed,first,..}=self;
                    let genesis=originals.genesis.as_ref().ok_or("removal-resume-genesis")?;
                    installed.verify_and_close(&genesis.raw[2],&genesis.raw[3],
                        &mut |point|removal_resume_point(book,originals,first,point))};
                check(installed==SignatureResult::SignatureVerified && self.installed.settled(),
                    self.first.unwrap_or("removal-resume-installed-signature"))?;
                let signer=native::install_producer::source_signer_data().ok_or("removal-resume-signer")?;
                check(producer_policy_matches_data(self.descriptor.signing_policy_data(),signer.team_data(),signer.leaf_sha1_data(),
                    signer.leaf_sha256_data()),"removal-resume-signer")?;
                self.originals.input.content_post(book)?;
                check(removal_resume_hash(book,self.originals.program,64*1024*1024)?==self.originals.program_sha,
                    "removal-resume-program-hash")?;
                self.originals.genesis.as_ref().ok_or("removal-resume-genesis")?.content_post(book)?;
                self.originals.fixed_absence(book)?;
                check(self.first.is_none() && self.native_settled(),"removal-resume-native-finality")?;
                self.verified=true;self.authenticated_selection(book).map(|_|())
            }
            pub(super) fn authenticated_selection(&self,book:&Install)->Result<&ReleaseSetData> {
                check(self.verified && self.self_verified && self.first.is_none() && self.native_settled()
                    && self.program.custody().operation==native::install_producer::ProducerOperation::RemoveRecoveryProgram
                    && !self.program.custody().failed && !self.program.custody().unknown
                    && self.remove.custody().remove_signature_matched && self.installed.custody().signature_matched,
                    "removal-resume-authenticated-source")?;
                self.existing_maintenance_post(book)?;
                Ok(self.descriptor.release_set_data())
            }
            pub(super) fn genesis_data(&self,book:&Install)->Result<&maintenance::RemovalGenesisData> {
                self.authenticated_selection(book)?;
                self.originals.genesis.as_ref().map(|g|&g.data).ok_or("removal-resume-genesis")
            }
            pub(super) fn genesis_original(&self,book:&Install)->Result<usize> {
                self.authenticated_selection(book)?;
                self.originals.genesis.as_ref().map(|g|g.snapshot).ok_or("removal-resume-genesis")
            }
            pub(super) fn genesis_archive(&self,book:&Install)->Result<usize> {
                self.authenticated_selection(book)?;
                self.originals.genesis.as_ref().map(|g|g.archive).ok_or("removal-resume-genesis")
            }
        }
        impl RemovalResumeSource {
            pub(super) fn genesis_control_data(&self,book:&Install,path:&str)->Result<&maintenance::RemovalControlSpanData> {
                // Comparison-only label supplied by the same SOURCE generation
                // walker. This function never opens an encoded path.
                RemovalResumeGenesis::span(self.genesis_data(book)?,0,path)
            }
            pub(super) fn read_genesis_control(&self,book:&Install,path:&str)->Result<Vec<u8>> {
                let row=self.genesis_control_data(book,path)?;
                removal_resume_span(book,self.genesis_original(book)?,row,installation_record::INVENTORY_LIMIT)
            }
            pub(super) fn history_rows_data(&self)->Result<usize> {
                Ok(self.originals.genesis.as_ref().ok_or("removal-resume-genesis-missing")?.census.rows().len())
            }
            pub(super) fn history_storage_data(&self)->Result<u64> {
                Ok(self.originals.genesis.as_ref().ok_or("removal-resume-genesis-missing")?.census.storage_bytes())
            }
            pub(super) fn history_matches(&self,book:&Install,other:&maintenance::RemovalArchiveCensus)->Result<()> {
                self.authenticated_selection(book)?;
                let original=&self.originals.genesis.as_ref().ok_or("removal-resume-genesis-missing")?.census;
                check(original.rows().len()==other.rows().len() && original.storage_bytes()==other.storage_bytes(),"removal-resume-history-changed")?;
                for (a,b) in original.rows().iter().zip(other.rows()) {
                    check(a.name()==b.name() && a.identity()==b.identity() && a.flags()==b.flags() && a.app_data()==b.app_data()
                        && a.attempt_data()==b.attempt_data(),"removal-resume-history-changed")?;
                    for (a,b) in a.files().iter().zip(b.files()) {match (a,b) {
                        (None,None)=>(),(Some(a),Some(b))=>check(a.identity()==b.identity() && a.flags()==b.flags()
                            && a.len()==b.len() && a.digest()==b.digest() && a.shape_tag_data()==b.shape_tag_data(),"removal-resume-history-changed")?,
                        _=>return Err("removal-resume-history-changed")}}
                }Ok(())
            }
            pub(super) fn final_original_post(&self,book:&mut Install)->Result<()> {
                self.authenticated_selection(book)?;
                let genesis=self.originals.genesis.as_ref().ok_or("removal-resume-genesis-missing")?;
                // Physical eight-original-per-row POST, not the one-use fresh
                // snapshot scan-stage wrapper. No stage reset or body copy.
                maintenance::post_removal_archive_references(book,&genesis.census)?;
                genesis.content_post(book)?;self.authenticated_selection(book)?;Ok(())
            }
            fn pending_native_data(&self)->bool {
                [self.program.custody(),self.remove.custody(),self.installed.custody()].iter().any(removal_resume_pending_data)
            }
        }
        fn removal_resume_pending_data(c:&native::install_producer::ProducerCustody)->bool {
            use native::android_service_management::CellCustody as C;
            c.unknown || c.in_call || c.gate_entered || matches!(c.cell,C::Entering|C::Owned|C::Unknown)
        }
        fn removal_resume_observation_matches_data(first:[u8;32],second:[u8;32])->bool {
            first.iter().any(|byte|*byte!=0) && first==second
        }
        // Not a live-peer proof: this separate capability records actual new
        // EX under continuous R, after SOURCE/genesis + first full observation.
        struct RemovalResumeExclusion {reservation:usize,maintenance:usize}
        impl RemovalResumeExclusion {
            fn acquire(book:&mut Install,source:&RemovalResumeSource,first:&maintenance::RemovalResumeFirst)->Result<Self> {
                source.authenticated_selection(book)?;source.existing_maintenance_post(book)?;
                check(first.fingerprint.iter().any(|byte|*byte!=0) && !book.gate.entered && !book.gate.lock_attempted
                    && !book.gate.exclusive_acquired,"removal-resume-exclusion-once")?;
                let reservation=book.registration.participant.ok_or("removal-resume-r-original")?;
                let maintenance=source.existing_maintenance.ok_or("removal-resume-m-original")?;
                book.clock()?;book.gate.entered=true;book.gate.lock_attempted=true;
                #[allow(deprecated)]
                let result=fcntl::flock(book.fd(maintenance)?.as_raw_fd(),fcntl::FlockArg::LockExclusiveNonblock);
                result.map_err(|_|"removal-resume-maintenance-busy-or-refused")?;
                // Known actual return BEFORE clock/source veto; never retry.
                book.gate.exclusive_acquired=true;
                let value=Self{reservation,maintenance};value.post(book,source)?;Ok(value)
            }
            fn post(&self,book:&Install,source:&RemovalResumeSource)->Result<()> {
                source.authenticated_selection(book)?;source.existing_maintenance_post(book)?;
                check(book.registration.participant==Some(self.reservation) && source.existing_maintenance==Some(self.maintenance)
                    && book.gate.entered && book.gate.lock_attempted && book.gate.exclusive_acquired,
                    "removal-resume-exclusive-originals")?;book.clock()
            }
        }
        struct RemovalResumeReady {
            source:RemovalResumeSource,exclusion:RemovalResumeExclusion,observed:maintenance::RemovalResumeObservation,
            request:String,nonce:String,classification:mobile_release_desktop::macos_remove_record::ClassificationData,
        }
        impl RemovalResumeReady {
            fn post(&self,book:&Install)->Result<()> {
                self.exclusion.post(book,&self.source)?;
                check(self.observed.fingerprint_data()?.iter().any(|byte|*byte!=0),"removal-resume-observation-missing")?;
                self.observed.continuation_budget(book)?;book.clock()
            }
            fn payload_all_absent_data(&self)->bool {self.observed.plan.payload_all_absent_data()}
            fn authenticated_genesis<'a>(&'a self,book:&Install)->Result<(&'a maintenance::RemovalGenesisData,usize)> {
                self.post(book)?;Ok((self.source.genesis_data(book)?,self.source.genesis_original(book)?))
            }
            fn create(source:RemovalResumeSource,exclusion:RemovalResumeExclusion,observed:maintenance::RemovalResumeObservation,
                book:&Install,request:&str,nonce:&str)->Result<Self> {
                use mobile_release_desktop::{macos_remove_record::{self as record,ClassificationData as C},
                    macos_install_maintenance::CheckData as K};
                removal_hex_data::<16>(request)?;removal_hex_data::<16>(nonce)?;
                exclusion.post(book,&source)?;observed.continuation_budget(book)?;
                let genesis=source.originals.genesis.as_ref().ok_or("removal-resume-genesis-missing")?;
                // Fresh attempts cannot fill a sixty-fifth slot or recycle IDs
                // hidden in an observed partial writer. Existing failures stay.
                check(genesis.census.rows().len()<64,"removal-resume-attempt-bound")?;genesis.census.fresh(request,nonce)?;
                let binding=genesis.data.binding_data()?;
                let classification=binding.with_binding(|binding| {
                    let prior=record::RemovalRecordData::parse_data(&genesis.tip_raw,binding).map_err(|_|"removal-resume-tip-record")?;
                    check(prior.owned_bytes_data().is_some_and(|n|n<=2*record::RECORD_LIMIT),"removal-resume-record-memory")?;
                    // These Matches are reached ONLY from actual typed SOURCE,
                    // full immutable-control/subset observations and same EX;
                    // no parser/old admission constructed these originals.
                    let current=record::FreshObservationData {request_id:request,root_nonce:nonce,prior_record_sha256:prior.digest_data(),
                        source_purpose:K::Matches,exclusive_original:K::Matches,protected_controls:K::Matches,
                        remaining_roster:K::Matches,complete_namespace:K::Matches,
                        app_slots:observed.plan.app_slots_data(),payload:observed.plan.payload_presence_data()};
                    Ok(record::classify_data(&prior,current))
                })?;
                check(matches!(classification,C::WithdrawalObservedAfterAdmission|C::RemainingPayloadObserved
                    |C::PayloadAbsenceObservedAfterInterruptedRemoval|C::PayloadAbsenceReobserved),"removal-resume-prefix-namespace")?;
                let value=Self{source,exclusion,observed,request:request.into(),nonce:nonce.into(),classification};
                value.post(book)?;Ok(value)
            }
        }
        struct Parent {
            book: Install, entered: bool, command: Option<ManuallyDrop<Command>>, child: Option<Child>,
            source: Option<Source>, invocation: String, init_sha: String,
            maintenance: Option<maintenance::Observed>, request_export: Option<RequestExport>,
            producer: Option<ProducerAdmission>,
            removal: Option<RemovalAdmission>, removal_observed: Option<maintenance::RemovalObserved>,
            removal_request: Option<RemovalRequest>,
            removal_request_started: bool,
            removal_publication: Option<RemovalPublication>,
            removal_peer_started:bool,removal_peer_pending:bool,
            removal_peer_failure:Option<&'static str>,removal_peer_native_first:Option<(u32,u64)>,
            removal_peer_custody:Option<removal_peer_native::RemovalPeerCustody>,
            removal_exclusive_reobserve_started: bool,
            removal_snapshot: Option<RemovalSnapshot>,
            removal_payload_execution:Option<RemovalPayloadExecution>,
            removal_resume:Option<RemovalResumeSource>,removal_resume_ready:Option<RemovalResumeReady>,
            command_original: Option<usize>, output_original: Option<usize>,
            command_close: bool, output_close: bool, output_eof: bool, output_admitted: bool,
            wait: Option<ExitStatus>, wait_unknown: bool, termination_attempted: bool,
            errors: Vec<&'static str>, command_gate_kernel_retained: bool, parent_book_settled: bool,
        }
        impl Parent {
            fn new(deadline: Deadline) -> Result<Self> {
                // The original entry sample preceded argv collection, not just
                // input/gate admission. Do not renew it after argument work.
                deadline.check_work()?;
                Ok(Self { book:Install::with_worker_deadline(deadline,false),entered:false,
                    command:None,child:None,source:None,invocation:String::new(),init_sha:String::new(),maintenance:None,request_export:None,producer:None,
                    removal:None,removal_observed:None,
                    removal_request:None,
                    removal_request_started:false,
                    removal_publication:None,
                    removal_peer_started:false,removal_peer_pending:false,removal_peer_failure:None,
                    removal_peer_native_first:None,removal_peer_custody:None,
                    removal_exclusive_reobserve_started:false,
                    removal_snapshot:None,
                    removal_payload_execution:None,
                    removal_resume:None,removal_resume_ready:None,
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
            fn admit_and_go(&mut self, source: &str) -> Result<()> { self.admit_and_go_selected(source,None) }
            // Current-source/R-held inspection only. No entry dispatch, peer,
            // durable admission, writer GO or success receipt is enabled here.
            // Private, purpose-exclusive preparation only. Neither remove
            // argv form nor installer entry dispatches here in this slice.
            fn admit_removal_resume(&mut self,completed:&str,request:&str,nonce:&str)->Result<()> {
                check(!self.entered && self.producer.is_none() && self.removal.is_none()
                    && self.removal_resume.is_none() && self.removal_resume_ready.is_none(),"worker-parent-once")?;
                removal_hex_data::<16>(request)?;removal_hex_data::<16>(nonce)?;
                self.entered=true;
                // Constructor contains no retained native verifier call. Store
                // the SAME raw/control/FD owner BEFORE its first such call.
                self.removal_resume=Some(RemovalResumeSource::new(&mut self.book,completed)?);
                let source=self.removal_resume.as_mut().ok_or("removal-resume-source-missing")?;
                source.inspect_self(&self.book)?;source.reserve_existing(&mut self.book)?;
                let (census,state)=maintenance::removal_resume_prelude(&mut self.book,source)?;
                source.load_genesis(&mut self.book,census,state)?;source.inspect_signed_genesis(&self.book)?;
                let first=maintenance::observe_removal_resume(&mut self.book,source,None)?.into_first()?;
                // into_first drops the entire first plan before allocating the
                // second; retains only fixed fingerprint+count comparison DATA.
                let exclusion=RemovalResumeExclusion::acquire(&mut self.book,source,&first)?;
                let observed=maintenance::observe_removal_resume(&mut self.book,source,Some(&first))?;
                check(removal_resume_observation_matches_data(first.fingerprint,observed.fingerprint_data()?),"removal-resume-observation-changed")?;
                exclusion.post(&self.book,source)?;
                // All three native cells have known retirement before moving
                // backing out of Parent's pending holder. Failure does not
                // turn into peer/drain/unregister or old operation success.
                check(source.native_settled() && !source.pending_native_data(),"removal-resume-native-finality")?;
                observed.charge_retained(&mut self.book)?;
                let source=self.removal_resume.take().ok_or("removal-resume-source-missing")?;
                self.removal_resume_ready=Some(RemovalResumeReady::create(source,exclusion,observed,&self.book,request,nonce)?);
                self.removal_resume_ready.as_ref().ok_or("removal-resume-ready-missing")?.post(&self.book)
            }
            fn retain_unresolved_removal_resume(&mut self) {
                if !self.removal_resume.as_ref().is_some_and(RemovalResumeSource::pending_native_data)
                    && !self.removal_resume_ready.as_ref().is_some_and(|ready|ready.source.pending_native_data()){return;}
                // Memory-only unwind safety, no native call/close/retry. C may
                // retain raw4 pointers: retaining ONLY FDs is insufficient.
                self.book.unknown=true;
                for original in &mut self.book.originals {if let Some(fd)=original.fd.take(){
                    std::mem::forget(fd);original.state=State::KernelExitRetained;}}
                if let Some(source)=self.removal_resume.take(){std::mem::forget(source);}
                if let Some(ready)=self.removal_resume_ready.take(){std::mem::forget(ready);}
                self.parent_book_settled=false;
            }
            fn admit_removal_source(&mut self, completed_path: &str) -> Result<()> {
                check(!self.entered && self.producer.is_none() && self.removal.is_none(),"worker-parent-once")?;
                self.entered=true;
                self.removal=Some(RemovalAdmission::new(&mut self.book,completed_path)?);
                let source=self.removal.as_mut().ok_or("removal-original-missing")?;
                source.inspect(&self.book)?;
                self.book.registration_before_maintenance(source.root_original())?;
                // R acquisition does not promote a stale pre-R signature or
                // code snapshot: actual originals are checked again now.
                source.reservation_post(&self.book)?;
                source.admit_existing_maintenance(&mut self.book)?;
                self.removal_observed=Some(maintenance::observe_removal(&mut self.book,source)?);
                source.bind_inventory(&self.book,self.removal_observed.as_ref().ok_or("removal-current-missing")?)
            }
            fn acquire_removal_exclusion(&mut self,peer:RemovalPeerCompletion)->Result<RemovalExclusion> {
                let source=self.removal.as_ref().ok_or("removal-original-missing")?;
                let request=self.removal_request.as_ref().ok_or("removal-request-missing")?;
                let observed=self.removal_observed.as_ref().ok_or("removal-current-missing")?;
                source.reservation_post(&self.book)?; source.existing_maintenance_post(&self.book)?;
                request.post(&self.book,source,observed)?;
                let retired=peer.retired();
                check(retired.role()==native::removal_coordinator::RemovalPeerRole::Parent
                    && retired.original_peer_exit_observed() && retired.peer_pid_data()>0
                    && retired.binding_data()==&request.native,"removal-peer-exit-required")?;
                let reservation=self.book.registration.participant.ok_or("removal-original-reservation")?;
                let maintenance=source.existing_maintenance.ok_or("removal-existing-maintenance")?;
                self.book.clock()?;
                // Sole attempt; known acquisition is retained even when the
                // subsequent clock/source check refuses. R is never closed.
                self.book.gate.entered=true;
                self.book.gate.lock_attempted=true;
                #[allow(deprecated)]
                let result=fcntl::flock(self.book.fd(maintenance)?.as_raw_fd(),fcntl::FlockArg::LockExclusiveNonblock);
                result.map_err(|_|"removal-maintenance-busy-or-refused")?;
                self.book.gate.exclusive_acquired=true;
                let exclusion=RemovalExclusion { peer,reservation,maintenance };
                exclusion.post(&self.book,source)?;
                Ok(exclusion)
            }
            fn reobserve_removal_exclusive(&mut self,exclusion:&RemovalExclusion)->Result<()> {
                check(!self.removal_exclusive_reobserve_started,"removal-reobserve-once")?;
                self.removal_exclusive_reobserve_started=true;
                let source=self.removal.as_ref().ok_or("removal-original-missing")?;
                exclusion.post(&self.book,source)?;
                maintenance::RemovalSnapshotCapture::begin(&mut self.book,source.root_original())?;
                maintenance::RemovalPayloadPlan::begin(&mut self.book)?;
                let old=self.removal_observed.take().ok_or("removal-current-missing")?;
                self.removal_observed=Some(maintenance::reobserve_removal_exclusive(&mut self.book,source,exclusion,old)?);
                exclusion.post(&self.book,source)?;
                let prior=maintenance::take_removal_archive_census(&mut self.book)?;
                self.book.removal_snapshot_capture.as_mut().ok_or("removal-snapshot-capture-missing")?.finish(prior)?;
                self.book.removal_payload_plan.as_mut().ok_or("removal-payload-plan-missing")?.finish()
            }
            fn remove_admitted_payload(&mut self,admission:RemovalSnapshotAdmission,exclusion:RemovalExclusion)->Result<RemovalPayloadAbsence> {
                check(self.removal_payload_execution.is_none() && self.removal.as_ref().is_some_and(RemovalAdmission::settled)
                    && self.removal_observed.is_some() && self.removal_snapshot.is_some()
                    && self.book.removal_payload_plan.as_ref().is_some_and(|plan|plan.complete),"removal-payload-transfer")?;
                // All values are existing same-owner originals. Store them
                // before any original close/native mutation can return.
                let source=self.removal.take().ok_or("removal-payload-source")?;
                let observed=self.removal_observed.take().ok_or("removal-payload-observation")?;
                let snapshot=self.removal_snapshot.take().ok_or("removal-payload-snapshot")?;
                let plan=self.book.removal_payload_plan.take().ok_or("removal-payload-plan")?;
                self.removal_payload_execution=Some(RemovalPayloadExecution::new(source,observed,snapshot,admission,exclusion,plan));
                self.removal_payload_execution.as_mut().ok_or("removal-payload-transfer")?.run(&mut self.book)
            }

            fn persist_removal_admission(&mut self,exclusion:&RemovalExclusion)->Result<RemovalSnapshotAdmission> {
                check(self.removal_snapshot.is_none(),"removal-snapshot-once")?;
                let capture=self.book.removal_snapshot_capture.take().ok_or("removal-snapshot-capture-missing")?;
                self.removal_snapshot=Some(RemovalSnapshot::new(capture));
                self.removal_snapshot.as_mut().ok_or("removal-snapshot-missing")?.prepare(&mut self.book,
                    self.removal.as_ref().ok_or("removal-original-missing")?,
                    self.removal_observed.as_ref().ok_or("removal-current-missing")?,
                    self.removal_request.as_ref().ok_or("removal-request-missing")?,exclusion)
            }
            fn prepare_removal_request(&mut self)->Result<()> {
                check(self.entered && !self.removal_request_started && self.removal_request.is_none(),"removal-request-once")?;
                self.removal_request_started=true;
                let source=self.removal.as_ref().ok_or("removal-original-missing")?;
                let observed=self.removal_observed.as_ref().ok_or("removal-current-missing")?;
                self.removal_request=Some(RemovalRequest::new(&self.book,source,observed)?);
                let fields=self.removal_request.as_ref().ok_or("removal-request-missing")?.data.binding_data().fields_data();
                maintenance::removal_archive_fresh_request(&self.book,fields.request_id,fields.root_nonce)?;
                self.removal_request.as_ref().ok_or("removal-request-missing")?.post(&self.book,source,observed)
            }
            fn prepare_removal_publication(&mut self)->Result<()> {
                check(self.removal_publication.is_none(),"removal-request-publication-once")?;
                // Store the ledger before the first potentially mutating call.
                // Failure retains only our original Book/effects; no retry,
                // foreign-directory removal or implicit publication is allowed.
                self.removal_publication=Some(RemovalPublication::new());
                self.removal_publication.as_mut().ok_or("removal-request-publication-missing")?.prepare(
                    &mut self.book,self.removal.as_ref().ok_or("removal-original-missing")?,
                    self.removal_observed.as_ref().ok_or("removal-current-missing")?,
                    self.removal_request.as_ref().ok_or("removal-request-missing")?)
            }
            fn join_removal_peer(&mut self,ready_hint:fn(&str)->Result<()>)->Result<RemovalPeerCompletion> {
                check(self.entered && !self.removal_peer_started && !self.removal_peer_pending
                    && self.producer.is_none() && self.child.is_none(),"removal-peer-once")?;
                self.removal_peer_started=true;
                let result=(|| {
                    let source=self.removal.as_ref().ok_or("removal-original-missing")?;
                    let observed=self.removal_observed.as_ref().ok_or("removal-current-missing")?;
                    let request=self.removal_request.as_ref().ok_or("removal-request-missing")?;
                    let publication=self.removal_publication.as_ref().ok_or("removal-request-publication-missing")?;
                    let (context,effects)=RemovalPeerContext::new(&self.book,source,observed,request,publication)?;
                    let originals=context.native_originals()?;
                    // Store outside the borrowed scope before allocation or
                    // callbacks. A panic/unknown must not free their backing.
                    self.removal_peer_pending=true;
                    let scope=removal_peer_scoped(&context,effects,originals,ready_hint);
                    // Original returned custody first, later clock/source veto
                    // second. Known consumes do not become Unknown merely late.
                    self.removal_peer_custody=scope.custody;
                    self.removal_peer_native_first=scope.native_first;
                    self.removal_peer_pending=!scope.settled;
                    if let Some(error)=scope.first { self.removal_peer_failure.get_or_insert(error); }
                    let (complete,effects)=scope.into_completion(&request.native)?;
                    // Full positive work POST AFTER actual exit, all native
                    // consumes and the final native retirement. Hard-reserve
                    // settlement alone cannot admit the subsequent M phase.
                    context.post(&effects)?;
                    let directory=context.directory;
                    let identity=context.directory_post(&effects)?;
                    context.book.clock()?;
                    // All native borrows are now gone. Only this real returned
                    // Bind's exact held/named requestdir baseline advances Book.
                    // No source/app/system-root identity is refreshed here.
                    self.book.originals[directory].identity=Some(identity);
                    self.book.check_name(directory,true)?;
                    self.removal_request.as_ref().ok_or("removal-request-missing")?.post(&self.book,
                        self.removal.as_ref().ok_or("removal-original-missing")?,
                        self.removal_observed.as_ref().ok_or("removal-current-missing")?)?;
                    self.book.shared_deadline()?.check_work()?;
                    Ok(complete)
                })();
                if let Err(error)=&result { self.removal_peer_failure.get_or_insert(*error);self.note(*error); }
                result
            }
            fn retain_unresolved_removal_peer(&mut self) {
                if !self.removal_peer_pending { return; }
                // MEMORY-ONLY retention, never native/FD cleanup or a join.
                // C copied the raw4 pointers into its retained cell; taking
                // and forgetting their Vec owners preserves those SAME heap
                // allocations. The synchronous callback/context was never
                // retained. No operation may resume this forgotten peer.
                self.book.unknown=true;
                for original in &mut self.book.originals {
                    if let Some(fd)=original.fd.take() {
                        std::mem::forget(fd);original.state=State::KernelExitRetained;
                    }
                }
                if let Some(source)=self.removal.take() { std::mem::forget(source); }
                if let Some(request)=self.removal_request.take() { std::mem::forget(request); }
                if let Some(observed)=self.removal_observed.take() { std::mem::forget(observed); }
                self.parent_book_settled=false;
            }
            fn admit_and_go_selected(&mut self, source: &str, selected: Option<(ReleaseSetData, &str)>) -> Result<()> {
                self.admit_and_go_inputs(source,selected,None)
            }
            fn admit_and_go_inputs(&mut self, source: &str, selected: Option<(ReleaseSetData, &str)>,
                completed_path: Option<&str>) -> Result<()> {
                check(!self.entered && !(selected.is_some() && completed_path.is_some()), "worker-parent-once")?;
                self.entered = true;
                let mut selected = selected.map(|(set,request)| (set,request.to_owned()));
                // Existing fixture destinations have their own original owner.
                // B3 will integrate a reviewed fixed fixture route, not a path flag.
                check(!cfg!(feature = "macos-installed-installer-fixture"), "worker-fixture-route-unavailable")?;
                let (input,inventory,inventory_bytes) = self.book.input(source)?;
                let actual = self.book.worker_source(source,input)?;
                // Authenticate fixed self/source before even the parent's fixed
                // ancestor/gate creation; the child remains the sole payload writer.
                self.book.source_post(&actual)?;
                if let Some(completed_path) = completed_path {
                    // Store all inert verifier wrappers before their first call.
                    // A failed/unknown native return cannot drop the original
                    // borrowed code directories into an unrelated close path.
                    self.producer = Some(ProducerAdmission::new(&mut self.book,&actual,completed_path)?);
                    let producer = self.producer.as_mut().ok_or("producer-original-missing")?;
                    let releases = producer.inspect(&self.book,&actual)?;
                    let request = if let Some(request) = producer.input.request_id_data() { request.to_owned() }
                        else {
                            let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "maintenance-request-random")?;
                            let request: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
                            transaction::export_name_data(&request).map_err(|_| "maintenance-request-random")?;
                            request
                        };
                    selected = Some((releases,request));
                }
                let mut nonce = [0u8;16]; getrandom::fill(&mut nonce).map_err(|_| "worker-invocation")?;
                self.invocation = nonce.iter().map(|b| format!("{b:02x}")).collect();
                check(invocation_valid(&self.invocation), "worker-invocation")?;
                if let Some((selected,request_id)) = selected {
                    maintenance::selected_compile(&selected)?;
                    transaction::export_name_data(&request_id).map_err(|_| "maintenance-request-shape")?;
                    check(request_id != self.invocation, "maintenance-request-invocation-reused")?;
                    let prepared = self.book.prepare_maintenance_input(input,inventory,inventory_bytes)?;
                    let mut observed = maintenance::observe(&mut self.book,prepared,selected,None)?;
                    if let Some(producer) = &self.producer {
                        observed.incoming_controls(&self.book,producer.input.descriptor_data(),producer.input.signature_data())?;
                    }
                    self.book.registration_complete_admitted(observed.prepared.destination, observed.action)?;
                    // This fixed sibling is reserved before intent or worker
                    // payload. Request spelling supplies correlation, not EX,
                    // producer trust, a source tuple, or package identity.
                    self.request_export = Some(RequestExport::reserve(&mut self.book,observed.prepared.destination,&request_id)?);
                    self.request_export.as_ref().ok_or("maintenance-request-missing")?.persist_reservation(&mut self.book)?;
                    observed.create_intent(&mut self.book,&self.invocation,&request_id)?;
                    self.maintenance = Some(observed);
                } else { let _prepared = self.book.prepare_fresh_input(input,inventory,inventory_bytes)?; }
                let gate = self.book.gate.participant.ok_or("worker-gate-original")?;
                check(self.book.gate.exclusive_acquired && self.book.gate.lock_attempted, "worker-parent-exclusive-required")?;
                self.book.gate_protected(gate)?; self.book.registration_ready()?; self.book.source_post(&actual)?;
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
                let mut init = json!({"schemaVersion":2,"kind":"private-writer-init","invocation":self.invocation,"endNanos":end,
                    "parent":parent,"child":child,"compile":compile_binding()?,"source":source_data(&self.book,actual)?,
                    "gate":identity_data(self.book.identity(gate)?),
                    "parentCommandEndpoint":command_before,"parentResultEndpoint":result_before});
                if let Some(observed) = &self.maintenance { init["maintenance"] = observed.binding(&self.book)?; }
                let bytes = serde_json::to_vec(&init).map_err(|_| "worker-frame-json")?;
                self.init_sha = hash(&bytes);
                write_frame(self.book.fd(command_n)?.as_fd(), &init, INIT_LIMIT, self.book.shared_deadline()?, true)?;
                let ready = read_frame(self.book.fd(output_n)?.as_fd(), CONTROL_LIMIT, self.book.shared_deadline()?)?.0;
                let worker_command = &ready["writerCommandEndpoint"];
                let worker_result = &ready["writerResultEndpoint"];
                pipe_shape(worker_command)?; pipe_shape(worker_result)?;
                valid_control(&ready,&control("ready",&self.invocation,&self.init_sha,end,parent,child,worker_command,worker_result))?;
                self.book.source_post(actual)?; self.book.gate_protected(gate)?; self.book.registration_ready()?;
                if let Some(request) = &self.request_export { request.empty_original(&self.book)?; }
                // XNU gives opposite pipe endpoints different inode facts.
                // Recheck each OWN original; remote endpoint numbers confer no authority.
                check(command_before == pipe_data(self.book.fd(command_n)?.as_fd(),true,self.book.shared_deadline()?)?
                    && result_before == pipe_data(self.book.fd(output_n)?.as_fd(),false,self.book.shared_deadline()?)?,
                    "worker-pipe-post")?;
                self.original_wait(); check(self.wait.is_none() && !self.wait_unknown, "worker-exited-before-go")?;
                self.producer_post(true)?; // Same originals/content again, BEFORE the sole GO.
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
            fn run_fresh(&mut self, source: &str) -> Result<JoinedWriter> { self.run_selected(source,None) }
            // The ordinary entry must authenticate the actual completed package,
            // expected producer tuple and Developer-ID purpose before calling.
            // This fixed request is only correlation; there is no trusted bool,
            // arbitrary path, ambient identity, or fixture fallback.
            fn run_maintenance(&mut self, source: &str, selected: ReleaseSetData, request_id: &str) -> Result<JoinedWriter> {
                self.run_selected(source,Some((selected,request_id)))
            }
            fn run_selected(&mut self, source: &str, selected: Option<(ReleaseSetData, &str)>) -> Result<JoinedWriter> {
                self.run_inputs(source,selected,None)
            }
            fn run_completed(&mut self, source: &str, completed_path: &str) -> Result<JoinedWriter> {
                self.run_inputs(source,None,Some(completed_path))
            }
            fn producer_post(&self, content: bool) -> Result<()> {
                if let Some(producer) = &self.producer {
                    producer.authenticated_post(&self.book,self.source.as_ref().ok_or("worker-source-original")?,content)?;
                    if let Some(observed) = &self.maintenance { observed.controls_post(&self.book)?; }
                }
                Ok(())
            }
            fn run_inputs(&mut self, source: &str, selected: Option<(ReleaseSetData, &str)>,
                completed_path: Option<&str>) -> Result<JoinedWriter> {
                check(!self.entered, "worker-parent-once")?;
                if let Err(error) = self.admit_and_go_inputs(source,selected,completed_path) { self.note(error); }
                if self.child.is_none() { return Err(self.errors.first().copied().unwrap_or("worker-original-child")); }
                let bytes = match self.collect() {
                    Ok(bytes) => bytes, Err(error) => { self.note(error); return Err(error); }
                };
                let value = packet(&bytes,RESULT_LIMIT)?;
                let outcome = PreExit::parse(&value,&self.invocation,&self.init_sha)?;
                check(match (&self.maintenance,&outcome.maintenance) {
                    (None,None) => true,
                    (Some(observed),Some(returned)) => observed.action == returned.action,
                    _ => false,
                },"maintenance-returned-action")?;
                let source_post = self.source.as_ref().is_some_and(|source| self.book.source_post(source).is_ok());
                if !source_post { self.note("worker-source-post"); }
                if let Err(error) = self.producer_post(true) { self.note(error); }
                let observed_at = self.book.shared_deadline()?.check_total()?;
                let status = self.wait.as_ref().and_then(ExitStatus::code);
                check(joined_data(true,self.output_eof,self.output_close,self.command_close,status,outcome.exit,
                    source_post,true,self.wait_unknown || !self.errors.is_empty()), "worker-joined-result-refused")?;
                let child = self.child.as_ref().ok_or("worker-original-child")?.id();
                Ok(JoinedWriter { invocation:self.invocation.clone(),child,outcome,observed_at })
            }
            fn record_maintenance_capsule(&mut self, joined: &JoinedWriter) -> Result<Value> {
                // Only this SAME retained Child can supply this native fact.
                // This writes no attestation about the parent's future exit or
                // its retained Command/gate references; outer entry owns that.
                check(joined.invocation == self.invocation && self.child.as_ref().is_some_and(|child| child.id() == joined.child)
                    && self.wait.as_ref().and_then(ExitStatus::code) == Some(joined.outcome.exit)
                    && self.output_eof && self.output_close && self.command_close && !self.wait_unknown && self.errors.is_empty(),
                    "maintenance-original-join-required")?;
                self.book.shared_deadline()?.check_work()?;
                self.producer_post(false)?; self.book.registration_ready()?;
                check(joined.observed_at < self.book.shared_deadline()?.original_endpoint(),"maintenance-original-join-deadline")?;
                let observed = self.maintenance.as_mut().ok_or("maintenance-observation-missing")?;
                let request = self.request_export.as_ref().ok_or("maintenance-request-missing")?;
                request.empty_original(&self.book)?;
                check(observed.intent.as_ref().ok_or("maintenance-intent-missing")?.request_id_data() == request.request_id,
                    "maintenance-request-binding")?;
                let returned = joined.outcome.maintenance.as_ref().ok_or("maintenance-result-shape")?;
                check(returned.action == observed.action,"maintenance-returned-action")?;
                let state = maintenance::state_after_join(&mut self.book,observed,&self.invocation,
                    returned.state_bytes.as_deref(),returned.inverse)?;
                let writer_known = joined.outcome.originals && joined.outcome.payload && joined.outcome.timely && !joined.outcome.unknown;
                let outcome = if !writer_known { transaction::RecordedOutcomeData::Unknown }
                    else { match joined.outcome.state.as_str() {
                        "installed" => transaction::RecordedOutcomeData::Applied,
                        "same-package" => transaction::RecordedOutcomeData::SamePackage,
                        "restored-app" => transaction::RecordedOutcomeData::RestoredApp,
                        "inverse-recorded" => transaction::RecordedOutcomeData::InverseRecorded,
                        "partial-installation-retained" => transaction::RecordedOutcomeData::Partial,
                        "refused-staging-retained" => transaction::RecordedOutcomeData::Refused,
                        _ => transaction::RecordedOutcomeData::Unknown,
                    }};
                let current = state.as_ref().map(transaction::StateData::current_data);
                if writer_known && joined.outcome.exit == 0 {
                    let producer = self.producer.as_ref().ok_or("producer-original-missing")?;
                    observed.publish_controls(&mut self.book,state.as_ref().ok_or("maintenance-producer-state")?,
                        producer.input.descriptor_data(),producer.input.signature_data())?;
                }
                let capsule = transaction::CapsuleData::encode_data(observed.intent.as_ref().ok_or("maintenance-intent-missing")?,
                    observed.previous(),state.as_ref(),current.as_ref().map(transaction::GenerationData::release_data),outcome,
                    transaction::WriterObservationData { returned:true,exit_code:Some(u8::try_from(joined.outcome.exit).map_err(|_| "maintenance-result-shape")?),
                        original_joined:true,result_eof:self.output_eof,original_closes_known:joined.outcome.originals && self.output_close && self.command_close,
                        within_original_deadline:joined.outcome.timely,payload_write_count:joined.outcome.writes,payload_write_bytes:joined.outcome.bytes },
                    &observed.selected).map_err(|_| "maintenance-capsule-binding")?;
                maintenance::persist_capsule(&mut self.book,observed,&self.invocation,&capsule)?;
                self.book.source_post(self.source.as_ref().ok_or("worker-source-original")?)?;
                Ok(json!({"schemaVersion":2,"kind":"maintenance-parent-pending-finalization","invocation":self.invocation,
                    "requestId":request.request_id,"resultName":request.name,
                    "resultFinality":"pending-own-write-readback-close-and-outer-return",
                    "action":observed.action,"writerState":joined.outcome.state,"writerExit":joined.outcome.exit,
                    "intentSha256":observed.intent.as_ref().ok_or("maintenance-intent-missing")?.digest_data(),
                    "stateSha256":state.as_ref().map(transaction::StateData::digest_data),"capsuleSha256":hash(&capsule),
                    "payloadWriteCount":joined.outcome.writes,"payloadWriteBytes":joined.outcome.bytes,
                    "originalWriterJoined":true,"parentFinality":"pending-original-closes-and-outer-return",
                    "registrationReservation":self.book.registration_record(),
                    "retainedGate":"parent-command-reference-until-kernel-exit","historicalOuterExit":"unverified"}))
            }
            fn record_maintenance_export(&mut self, joined: &JoinedWriter) -> Result<Value> {
                let record = self.record_maintenance_capsule(joined)?;
                self.request_export.as_mut().ok_or("maintenance-request-missing")?.publish(&mut self.book,&record)?;
                self.book.source_post(self.source.as_ref().ok_or("worker-source-original")?)?;
                self.producer_post(false)?;
                // The exported bytes cannot attest these following closes or
                // this process's future return. The actual entry must settle its
                // book and preserve Command/OFD to kernel exit; the outer caller
                // requires original Installer0 and exact correlated readback.
                Ok(record)
            }
            fn settle_parent_originals(&mut self) -> bool {
                if self.removal_peer_pending {
                    self.retain_unresolved_removal_peer();
                    self.note("removal-peer-custody-retained");
                    self.settlement_time();return false;
                }
                // B3 invokes this only after its parent's evidence writers.
                // The one-use Command/config OFD remains KernelExitRetained:
                // its Drop would not provide an errno-observed close receipt.
                self.close_command();
                if let Some(n) = self.output_original.take() {
                    if !self.book.close(n) { self.note("worker-result-close-unknown"); }
                }
                if self.wait_unknown || self.child.is_some() && self.wait.is_none() { self.book.unknown = true; }
                // Native references may still borrow these exact book FDs.
                // Retire them under this original clock BEFORE any book close.
                let producer_settled = self.producer.as_mut().is_none_or(|producer| producer.settle(&self.book));
                let removal_settled = self.removal.as_mut().is_none_or(|removal| removal.settle(&self.book));
                let payload_settled=self.removal_payload_execution.as_ref().is_none_or(|owner|owner.source.settled());
                let resume_settled=self.removal_resume.as_mut().is_none_or(|source|source.settle(&self.book));
                let resume_ready_settled=self.removal_resume_ready.as_mut().is_none_or(|ready|ready.source.settle(&self.book));
                let native_settled=producer_settled && removal_settled && payload_settled && resume_settled && resume_ready_settled;
                if !resume_settled || !resume_ready_settled {self.retain_unresolved_removal_resume();}
                if native_settled { self.parent_book_settled = self.book.settle_originals(); }
                else {
                    self.note("producer-native-finality-unknown");
                    self.book.unknown = true;
                    for original in &mut self.book.originals {
                        if let Some(fd) = original.fd.take() {
                            std::mem::forget(fd);
                            original.state = State::KernelExitRetained;
                        }
                    }
                    // Neither the borrowed descriptors nor an unknown native
                    // cell are consumed by a Drop/replacement owner. The actual
                    // outer process return is still required for kernel exit.
                    self.parent_book_settled = false;
                }
                self.settlement_time();
                self.parent_book_settled
            }
        }
        impl Drop for Parent {
            fn drop(&mut self) {
                // An unwind must not free backing still referenced by an
                // unretired native cell. This guard only leaks our unresolved
                // allocations/FDs to actual process exit; it performs no IO,
                // no close/retire, no retry and cannot report success.
                self.retain_unresolved_removal_peer();
                self.retain_unresolved_removal_resume();
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
        enum PreparedWorker { Fresh(PreparedFresh), Maintenance(maintenance::Observed) }
        fn prepare_worker(book: &mut Install, init: &Value, gate_fd: BorrowedFd<'_>, invocation: &str, end: u64) -> Result<PreparedWorker> {
            let maintenance_value = init.get("maintenance");
            if maintenance_value.is_some() {
                object(init,&["schemaVersion","kind","invocation","endNanos","parent","child","compile","source","gate", "parentCommandEndpoint","parentResultEndpoint","maintenance"])?;
            } else { object(init,&["schemaVersion","kind","invocation","endNanos","parent","child","compile","source","gate","parentCommandEndpoint","parentResultEndpoint"])?; }
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
                .and_then(|n| n.checked_add((paths::MAINTENANCE_GATE_BYTES.len() + paths::REGISTRATION_GATE_BYTES.len()) as u64))
                .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT)
                && index.files.len().checked_add(4).is_some_and(|n| n <= installation_record::FILE_LIMIT), "inventory-bound")?;
            let source = book.worker_source(&source_path,input)?;
            check(init["source"] == source_data(book,&source)?, "worker-source-binding")?;
            let support = book.support_root()?;
            let destination = book.open(Some(support),"MobileReleaseKit",true)?;
            book.protected(destination,true,Some(0o755))?;
            let versions = book.open(Some(destination),"versions",true)?;
            book.protected(versions,true,Some(0o755))?;
            if maintenance_value.is_none() { book.absent(destination,paths::APP_NAME)?; book.absent(versions,paths::RELEASE)?; }
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
            let prepared = PreparedFresh { input,inventory,inventory_bytes,destination,versions };
            if let Some(value) = maintenance_value {
                let selected = maintenance::Observed::selected_from_binding(value)?;
                let mut observed = maintenance::observe(book,prepared,selected,Some(invocation))?;
                let request_id = value["requestId"].as_str().ok_or("maintenance-request-shape")?;
                observed.read_intent(book,invocation,request_id)?;
                check(observed.binding(book)? == *value,"maintenance-init-binding")?;
                Ok(PreparedWorker::Maintenance(observed))
            } else { Ok(PreparedWorker::Fresh(prepared)) }
        }
        fn dispatch_private(args: &[String]) -> i32 {
            // The deadline is decoded BEFORE the first potentially blocking read.
            let admitted: Result<(Deadline, u64)> = (|| {
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
                let destination = match &prepared {
                    PreparedWorker::Fresh(prepared) => prepared.destination,
                    PreparedWorker::Maintenance(observed) => observed.prepared.destination,
                };
                book.registration_after_go(destination)?;
                match prepared {
                    PreparedWorker::Fresh(prepared) => book.install_prepared(prepared,&args[3]),
                    PreparedWorker::Maintenance(observed) => maintenance::execute(&mut book,observed,&args[3]),
                }
            })();
            let result = book.finish(attempt);
            let outcome = PreExit::from_original(&book,&result);
            // No claim to have closed fd1/fd2 or joined ourselves. The parent's
            // actual EOF and original wait can later establish those facts.
            let sent = book.shared_deadline().and_then(|deadline|
                write_frame(stdout.as_fd(),&outcome.data(&args[3],&init_sha),RESULT_LIMIT,deadline,false));
            if sent.is_ok() { result.exit } else if result.exit == 0 { 1 } else { result.exit }
        }
        const ARGUMENT_LIMIT: usize = 1024;
        const ARGUMENT_BYTES_LIMIT: usize = 4096;
        #[derive(Debug,PartialEq,Eq)]
        enum EntryKind { CompletedPackage, PrivateWriter }
        fn entry_arguments_data(values: impl IntoIterator<Item=std::ffi::OsString>) -> Result<Vec<String>> {
            let mut result = Vec::with_capacity(4); let mut total = 0usize;
            // Read at most the four admitted values plus one refusal sentinel.
            // Never collect an unbounded iterator or replace invalid UTF-8.
            for value in values.into_iter().take(5) {
                let bytes = value.as_encoded_bytes();
                check(result.len() < 4 && !bytes.is_empty() && bytes.len() <= ARGUMENT_LIMIT
                    && !bytes.iter().any(|b| b.is_ascii_control()),"entry-argument-bound")?;
                total = total.checked_add(bytes.len()).filter(|n| *n <= ARGUMENT_BYTES_LIMIT).ok_or("entry-argument-bound")?;
                result.push(value.into_string().map_err(|_| "entry-argument-utf8")?);
            }
            Ok(result)
        }
        fn entry_kind_data(args: &[String]) -> Result<EntryKind> {
            match args {
                [_,source,completed] if source.starts_with('/') && completed.starts_with('/') => Ok(EntryKind::CompletedPackage),
                [_,role,endpoint,invocation] if role == ROLE && invocation_valid(invocation)
                    && endpoint.parse::<u64>().ok().is_some_and(|n| endpoint == &n.to_string()) => Ok(EntryKind::PrivateWriter),
                _ => Err("fixed-completed-package-input-required"),
            }
        }
        pub(super) fn entry() -> i32 {
            // This is the first original sample, BEFORE arguments or admission.
            let started = match monotonic() { Ok(value) => value, Err(_) => return 1 };
            let args = match entry_arguments_data(std::env::args_os()) { Ok(args) => args, Err(_) => return 1 };
            match entry_kind_data(&args) {
                Ok(EntryKind::PrivateWriter) => dispatch_private(&args), // Inherit, never renew the parent's endpoint.
                Ok(EntryKind::CompletedPackage) => completed_entry(&args[1],&args[2],started),
                Err(_) => 1,
            }
        }
        // Postinstall must supply ONLY the genuinely qualified completed outer
        // package field. A fixed spelling/UID/mount is not producer authority.
        fn completed_entry(source: &str, completed_path: &str, started: u64) -> i32 {
            let mut parent = match Deadline::from_entry(started).and_then(Parent::new) { Ok(parent) => parent, Err(_) => return 1 };
            let returned = parent.run_completed(source,completed_path);
            let mut writer_exit = None;
            let mut published = false;
            let mut exported = false;
            match returned {
                Ok(joined) => {
                    writer_exit = Some(joined.outcome.exit);
                    published = joined.outcome.runtime == "confirmed" || joined.outcome.app == "confirmed";
                    match parent.record_maintenance_export(&joined) {
                        Ok(_) => exported = true,
                        Err(error) => parent.note(error),
                    }
                }
                Err(error) => parent.note(error),
            }
            let originals = parent.settle_parent_originals();
            let native = parent.producer.as_ref().is_some_and(|producer| producer.signature.settled()
                && producer.entry.settled() && producer.payload.settled());
            let timely = parent.settlement_time();
            // These are actual completed observations, not the pending exported
            // document claiming its own future close or the parent's return.
            // The one retained Command/OFD survives this Rust value's Drop and
            // retires only when the caller immediately returns to main's exit.
            completed_exit_data(writer_exit,published,exported,originals,native,
                parent.command_gate_kernel_retained && parent.command.is_some(),timely,
                parent.errors.is_empty(),parent.book.unknown || parent.wait_unknown)
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
                let args = |values: &[&str]| entry_arguments_data(values.iter().map(|value| std::ffi::OsString::from(*value)));
                let outer = args(&["mrk-macos-install","/private/Script/input","/Volumes/Mobile Release Kit/Install.pkg"]).unwrap();
                assert_eq!(entry_kind_data(&outer),Ok(EntryKind::CompletedPackage));
                let private = args(&["mrk-macos-install",ROLE,"120000000001","11111111111111111111111111111111"]).unwrap();
                assert_eq!(entry_kind_data(&private),Ok(EntryKind::PrivateWriter));
                for values in [vec!["mrk-macos-install","/private/Script/input"],vec!["mrk-macos-install",ROLE,"/any.pkg"],
                    vec!["mrk-macos-install",ROLE,"0123","11111111111111111111111111111111"],
                    vec!["mrk-macos-install",ROLE,"123","00000000000000000000000000000000"],
                    vec!["mrk-macos-install","relative","/any.pkg"]] {
                    assert!(entry_kind_data(&args(&values).unwrap()).is_err());
                }
                for values in [vec!["a";5],vec![""],vec!["a\nb"],vec!["a\0b"]] { assert!(args(&values).is_err()); }
                assert!(entry_arguments_data([std::ffi::OsString::from("x".repeat(ARGUMENT_LIMIT+1))]).is_err());
                use std::os::unix::ffi::OsStringExt;
                assert!(entry_arguments_data([std::ffi::OsString::from_vec(vec![0xff])]).is_err());
                completed_package::fixed_source_data_checks();
            }
            fn removal_snapshot_data_checks() {
                let identity=Identity { dev:1,ino:2,mode:0o100444,uid:0,gid:0,links:1,size:3,
                    mtime:4,mtime_ns:5,ctime:6,ctime_ns:7 };
                let mut row=maintenance::RemovalSnapshotControl { path:"control.json".into(),identity,flags:0,
                    size:3,digest:Sha256::digest(b"raw").into(),kind:0,held:None };
                let mut same=maintenance::RemovalSnapshotControl { path:row.path.clone(),identity,flags:0,size:3,
                    digest:row.digest,kind:0,held:Some(99) };
                assert!(maintenance::removal_snapshot_control_equal_data(&row,&same));
                same.digest[0]^=1;assert!(!maintenance::removal_snapshot_control_equal_data(&row,&same));same.digest=row.digest;
                same.flags=1;assert!(!maintenance::removal_snapshot_control_equal_data(&row,&same));
                let frame=maintenance::removal_snapshot_frame_data(&row).unwrap();
                assert_eq!(frame[0],0);assert!(frame.ends_with(&row.digest));
                row.kind=5;assert!(maintenance::removal_snapshot_frame_data(&row).is_err());row.kind=0;
                row.size=0;assert!(maintenance::removal_snapshot_frame_data(&row).is_err());
                row.size=installation_record::INVENTORY_LIMIT as u64+1;
                assert!(maintenance::removal_snapshot_frame_data(&row).is_err());row.size=3;
                row.path="x".repeat(1025);assert!(maintenance::removal_snapshot_frame_data(&row).is_err());
                let name=format!(".remove-{}","1".repeat(32));
                assert!(removal_archive_name_data(&name));assert!(!removal_archive_name_data(&format!(".remove-{}","0".repeat(32))));
                assert!(maintenance::removal_snapshot_child_data(true,paths::APP_NAME,1));
                assert!(!maintenance::removal_snapshot_child_data(false,paths::APP_NAME,1));
                assert!(!maintenance::removal_snapshot_child_data(true,"Other App.app",1));
                assert!(!maintenance::removal_snapshot_child_data(true,paths::APP_NAME,0));
                let before=vec![("versions".into(),10),(paths::APP_NAME.into(),20)];
                let mut after:BTreeMap<String,u64>=before.iter().cloned().collect();after.insert(name.clone(),30);
                assert!(removal_snapshot_root_delta_data(&before,&after,&name,30));
                after.insert(paths::APP_NAME.into(),21);assert!(!removal_snapshot_root_delta_data(&before,&after,&name,30));
                after.insert(paths::APP_NAME.into(),20);after.insert("foreign".into(),31);
                assert!(!removal_snapshot_root_delta_data(&before,&after,&name,30));
                assert!(removal_snapshot_budget_data(4*1024*1024,1024,4096,50,256,12,4,0,40,3).is_ok());
                assert!(removal_snapshot_budget_data(16*1024*1024,1024,4096,50,50,12,4,0,40,3).is_err());
                assert!(removal_snapshot_budget_data(0,installation_record::PAYLOAD_LIMIT,1,0,0,0,0,0,0,0).is_err());
                assert!(removal_snapshot_budget_data(0,0,1,24576,24576,1,1,0,0,0).is_err());
                assert!(removal_snapshot_budget_data(0,0,1,0,0,0,0,0,91,0).is_err());
                assert!(removal_snapshot_budget_data(0,0,u64::MAX,0,0,0,0,0,0,0).is_err());
                assert!(removal_snapshot_budget_data(0,0,1,0,0,0,0,64,0,0).is_err());
                assert!(removal_snapshot_budget_data(0,0,1,0,0,0,0,63,0,0).is_ok());
                assert!(removal_snapshot_initial_history_data(63,false));
                assert!(!removal_snapshot_initial_history_data(64,false));
                assert!(!removal_snapshot_initial_history_data(1,true));
                let mut file=RemovalSnapshotFile::new();assert!(!file.settled_data());
                file.writer=Some(1);file.reader=Some(2);file.written=3;file.sealed=true;file.persisted=true;
                file.closed=true;file.directory_persisted=true;assert!(!file.settled_data());
                file.readback=true;assert!(file.settled_data());file.closed=false;assert!(!file.settled_data());
                // These supplied bits exercise the production finality reducer,
                // not a native fsync/close/old-writer success observation.
            }

            fn removal_resume_data_checks() {
                maintenance::removal_resume_observation_data_checks();
                assert!(removal_resume_path_data("/private/tmp/extracted/mrk-macos-remove"));
                for path in ["mrk-macos-remove","/mrk-macos-remove/","/a/../mrk-macos-remove","/a//mrk-macos-remove",
                    "/a/mrk-macos-install","/a/é/mrk-macos-remove","/a/./mrk-macos-remove"] {assert!(!removal_resume_path_data(path));}
                assert!(!removal_resume_path_data(&format!("/{}/mrk-macos-remove","a/".repeat(33))));
                assert!(removal_resume_observation_matches_data([1;32],[1;32]));
                assert!(!removal_resume_observation_matches_data([1;32],[2;32]));
                assert!(!removal_resume_observation_matches_data([0;32],[0;32]));
                let plain=native::install_producer::ProducerVerifier::new().custody();
                assert!(!removal_resume_pending_data(&plain));
                use native::android_service_management::CellCustody as C;
                for cell in [C::Entering,C::Owned,C::Unknown]{let mut value=plain;value.cell=cell;assert!(removal_resume_pending_data(&value));}
                for field in 0..3 {let mut value=plain;match field{0=>value.unknown=true,1=>value.in_call=true,_=>value.gate_entered=true};
                    assert!(removal_resume_pending_data(&value));}
                let mut retired=plain;retired.cell=C::Consumed;assert!(!removal_resume_pending_data(&retired));
                retired.unknown=true;assert!(removal_resume_pending_data(&retired));
            }
            fn removal_payload_data_checks() {
                use mobile_release_desktop::macos_remove_record::FailureKindData;
                // Actual production reducers only. These do not execute or
                // stand in for APFS rename/unlink/close/native qualification.
                assert_eq!(removal_payload_originals_data(3,4,5,6),Some(6+12+10+48+32));
                assert_eq!(removal_payload_originals_data(0,0,0,0),Some(32));
                assert!(removal_payload_originals_data(usize::MAX,0,0,0).is_none());
                assert!(removal_payload_originals_data(0,usize::MAX,0,0).is_none());
                assert!(removal_payload_originals_data(0,0,76,0).is_none());
                assert!(removal_payload_originals_data(0,0,0,64).is_none());
                let future=removal_payload_originals_data(3,4,5,6).unwrap();
                assert_eq!(removal_payload_original_budget_data(24576-future,3,4,5,6),Some((future,24576)));
                assert!(removal_payload_original_budget_data(24577-future,3,4,5,6).is_none());
                assert!(removal_payload_original_budget_data(usize::MAX,3,4,5,6).is_none());
                let obsolete=3+3*4+2*5+4*6+32;
                assert!(24576-obsolete+obsolete<=24576);
                assert!(removal_payload_original_budget_data(24576-obsolete,3,4,5,6).is_none());
                assert!(removal_payload_live_data(65,5));
                assert!(!removal_payload_live_data(66,5));
                assert!(!removal_payload_live_data(usize::MAX,0));
                let control=16*1024*1024;let progress=5*mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64;
                let storage=installation_record::PAYLOAD_LIMIT-progress-1;
                assert!(removal_payload_allocation_data(control-128,128,storage,1));
                assert!(!removal_payload_allocation_data(control-127,128,storage,1));
                assert!(!removal_payload_allocation_data(control-128,128,storage,2));
                assert!(!removal_payload_allocation_data(u64::MAX,1,storage,1));
                for phase in [RemovalPayloadPhase::OriginalSource,RemovalPayloadPhase::Transferred,
                    RemovalPayloadPhase::AppWithdrawn,RemovalPayloadPhase::Absent] {
                    assert!(!removal_payload_phase_allows_unlink_data(phase,true,false));
                }
                assert!(removal_payload_phase_allows_unlink_data(RemovalPayloadPhase::Removing,true,false));
                assert!(!removal_payload_phase_allows_unlink_data(RemovalPayloadPhase::Removing,false,false));
                assert!(!removal_payload_phase_allows_unlink_data(RemovalPayloadPhase::Removing,true,true));
                // Each actual cut may leave a complete sealed next-prefix
                // file, even though this operation cannot claim it settled.
                // The fresh-reader failure basis must agree, while unlink
                // still requires the original full slot3 settlement.
                for cut in 0..7 {
                    let mut file=RemovalSnapshotFile::new();file.writer=Some(1);
                    file.written=if cut==0{63}else{64};file.sealed=cut>=2;
                    file.persisted=cut>=3;file.closed=cut>=4;
                    if cut>=5 {file.reader=Some(2);file.readback=true;}
                    file.directory_persisted=cut>=6;
                    assert_eq!(removal_payload_sealed_record_data(64,file.written,file.sealed,true),cut>=2);
                    assert_eq!(file.settled_data(),cut==6);
                    assert_eq!(removal_payload_phase_allows_unlink_data(RemovalPayloadPhase::Removing,file.settled_data(),false),cut==6);
                    assert!(!removal_payload_phase_allows_unlink_data(RemovalPayloadPhase::Removing,file.settled_data(),true));
                }
                assert!(!removal_payload_sealed_record_data(64,63,true,true));
                assert!(!removal_payload_sealed_record_data(64,64,true,false));
                assert!(!removal_payload_sealed_record_data(0,0,true,true));
                assert!(!removal_payload_sealed_record_data(usize::MAX,u64::MAX,true,true));
                let before=Identity {dev:1,ino:2,mode:0o040755,uid:0,gid:0,links:4,size:80,
                    mtime:5,mtime_ns:1,ctime:6,ctime_ns:2};
                let actual=Identity {links:3,size:64,mtime:7,ctime:8,..before};
                assert!(removal_payload_parent_change_data(before,0,actual,0,actual,0));
                for foreign in [Identity {dev:2,..actual},Identity {ino:3,..actual},Identity {mode:0o040777,..actual},
                    Identity {uid:1,..actual},Identity {gid:1,..actual},Identity {mode:0o100444,..actual}] {
                    assert!(!removal_payload_parent_change_data(before,0,foreign,0,foreign,0));
                }
                assert!(!removal_payload_parent_change_data(before,0,actual,1,actual,1));
                assert!(!removal_payload_parent_change_data(before,0,actual,0,Identity {ctime:9,..actual},0));
                let mut roster=BTreeMap::from([("listed".to_owned(),4)]);
                let children=[("listed",4,RemovalNodeEffect::Present),("old",5,RemovalNodeEffect::Removed)];
                assert!(removal_payload_children_data(children.into_iter(),&roster));
                roster.insert("foreign".into(),6);
                assert!(!removal_payload_children_data(children.into_iter(),&roster));
                roster.remove("foreign");roster.insert("listed".into(),7);
                assert!(!removal_payload_children_data(children.into_iter(),&roster));
                roster.clear();
                assert!(!removal_payload_children_data(children.into_iter(),&roster));
                assert!(removal_payload_children_data([("listed",4,RemovalNodeEffect::Removed)].into_iter(),&roster));
                assert!(!removal_payload_children_data([("listed",4,RemovalNodeEffect::Unknown)].into_iter(),&roster));
                let mut states=vec![RemovalNodeState {original:None,effect:RemovalNodeEffect::Present,roster_observed:false,returned:None},
                    RemovalNodeState {original:None,effect:RemovalNodeEffect::Present,roster_observed:false,returned:None}];
                assert!(!removal_payload_app_last_data(0,0,&states));
                assert!(removal_payload_app_last_data(1,0,&states));
                states[1].effect=RemovalNodeEffect::Unknown;assert!(!removal_payload_app_last_data(0,0,&states));
                states[1].effect=RemovalNodeEffect::Removed;assert!(removal_payload_app_last_data(0,0,&states));
                let mut first=None;removal_payload_latch_data(&mut first,"actual-first",FailureKindData::Persistence);
                removal_payload_latch_data(&mut first,"later-close",FailureKindData::CloseUnknown);
                assert_eq!(first,Some(("actual-first",FailureKindData::Persistence)));
                assert_eq!((0..6).map(|slot|removal_payload_file_name(slot).unwrap()).collect::<Vec<_>>(),
                    ["snapshot-v2","admission.json","app-withdrawn.json","payload-roster-removal.json",
                        "payload-absent-observed.json","first-failure.json"]);
                assert!(removal_payload_file_name(6).is_err());
            }

            #[test]
            fn private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality() {
                removal_resume_data_checks();
                removal_payload_data_checks();
                maintenance::removal_archive_data_checks();
                removal_snapshot_data_checks();
                // A spaced fixed application leaf is not a general payload
                // component. This DATA probe cannot create a root original.
                let root=Identity { dev:1,ino:2,mode:0o040755,uid:0,gid:0,links:2,size:64,
                    mtime:1,mtime_ns:0,ctime:1,ctime_ns:0 };
                assert!(!component(paths::APP_NAME));
                assert!(installed_root_roster_alias_data(root,root,root,0,0));
                let mut own_changed=root; own_changed.mtime=2; own_changed.ctime=2;
                assert!(installed_root_roster_alias_data(root,own_changed,own_changed,0,0));
                for other in [Identity { ino:3,..root },Identity { dev:2,..root },
                    Identity { mode:0o040700,..root },Identity { uid:501,..root },
                    Identity { gid:20,..root },Identity { mode:0o100755,..root }] {
                    assert!(!installed_root_roster_alias_data(root,root,other,0,0));
                    assert!(!installed_root_roster_alias_data(root,other,other,0,0));
                }
                assert!(!installed_root_roster_alias_data(root,root,root,1,0));
                assert!(!installed_root_roster_alias_data(root,root,root,0,1));
                assert!(!installed_root_roster_alias_data(root,root,own_changed,0,0));
                assert!(installed_root_roster_child_data(paths::APP_NAME,true));
                assert!(!installed_root_roster_child_data(paths::APP_NAME,false));
                for bad in ["Other App.app","Mobile Release Kit.app/child","../Mobile Release Kit.app",".",".."] {
                    assert!(!installed_root_roster_child_data(bad,true));
                    assert!(!installed_root_roster_child_data(bad,false));
                }
                for ordinary in ["runtime","inventory.json",".remove-1234567890abcdef1234567890abcdef"] {
                    assert!(installed_root_roster_child_data(ordinary,false));
                    assert!(installed_root_roster_child_data(ordinary,true));
                }
                // Parent peer owns no replacement Book. Only the two typed
                // returned original effects can update its local expectations.
                // These DATA controls execute the actual callback reducer;
                // they do not pretend to bind/listen, own R or authenticate code.
                use removal_peer_native::{RemovalNativePhase as PeerNativePhase,RemovalOriginalData as PeerOriginal};
                let peer_directory=PeerOriginal { device:1,inode:20,links:2,size:64,mode:0o40755,
                    modified_seconds:1,changed_seconds:1,..PeerOriginal::default() };
                let bound_directory=PeerOriginal {links:3,size:128,modified_seconds:2,changed_seconds:2,..peer_directory};
                let bound_socket=PeerOriginal {device:1,inode:21,links:1,mode:0o140755,
                    modified_seconds:2,changed_seconds:2,..PeerOriginal::default()};
                let mode_socket=PeerOriginal {mode:0o140666,changed_seconds:3,..bound_socket};
                let initial=RemovalPeerOwnEffects::new_data(peer_directory).unwrap();
                for (phase,slot,before) in [(PeerNativePhase::Bind,None,true),(PeerNativePhase::Bind,Some(1),true),
                    (PeerNativePhase::Listen,Some(0),true),(PeerNativePhase::Bind,Some(0),false),
                    (PeerNativePhase::SocketMode,Some(0),true)] {
                    let mut attempt=initial;
                    assert!(attempt.transition_data(phase,slot,before,peer_directory,PeerOriginal::default()).is_err());
                    assert_eq!(attempt,initial);
                }
                let mut own=initial;
                own.transition_data(PeerNativePhase::Bind,Some(0),true,peer_directory,PeerOriginal::default()).unwrap();
                for wrong in [PeerOriginal{inode:99,..bound_directory},PeerOriginal{device:2,..bound_directory},
                    PeerOriginal{uid:501,..bound_directory},PeerOriginal{gid:20,..bound_directory},
                    PeerOriginal{mode:0o40777,..bound_directory},PeerOriginal{flags:1,..bound_directory}] {
                    let mut attempt=own;
                    assert!(attempt.transition_data(PeerNativePhase::Bind,Some(0),false,wrong,bound_socket).is_err());
                    assert_eq!(attempt,own);
                }
                for wrong in [PeerOriginal{inode:0,..bound_socket},PeerOriginal{device:2,..bound_socket},
                    PeerOriginal{uid:501,..bound_socket},PeerOriginal{gid:20,..bound_socket},
                    PeerOriginal{links:2,..bound_socket},PeerOriginal{mode:0o100755,..bound_socket},
                    PeerOriginal{mode:0o144755,..bound_socket},PeerOriginal{flags:1,..bound_socket}] {
                    let mut attempt=own;
                    assert!(attempt.transition_data(PeerNativePhase::Bind,Some(0),false,bound_directory,wrong).is_err());
                    assert_eq!(attempt,own);
                }
                own.transition_data(PeerNativePhase::Bind,Some(0),false,bound_directory,bound_socket).unwrap();
                assert_eq!(own.phase,RemovalPeerOwnPhase::Bound);
                assert_eq!(own.directory,bound_directory);assert_eq!(own.socket,Some(bound_socket));
                assert!(own.transition_data(PeerNativePhase::Bind,Some(0),true,bound_directory,bound_socket).is_err());
                own.transition_data(PeerNativePhase::SocketMode,Some(0),true,bound_directory,bound_socket).unwrap();
                for wrong in [PeerOriginal{inode:99,..mode_socket},PeerOriginal{size:1,..mode_socket},
                    PeerOriginal{mode:0o140777,..mode_socket},PeerOriginal{uid:1,..mode_socket},
                    PeerOriginal{gid:1,..mode_socket},PeerOriginal{links:2,..mode_socket},PeerOriginal{flags:1,..mode_socket},
                    PeerOriginal{modified_seconds:99,..mode_socket},PeerOriginal{modified_nanoseconds:1,..mode_socket}] {
                    let mut attempt=own;
                    assert!(attempt.transition_data(PeerNativePhase::SocketMode,Some(0),false,bound_directory,wrong).is_err());
                    assert_eq!(attempt,own);
                }
                assert!(own.transition_data(PeerNativePhase::SocketMode,Some(0),false,peer_directory,mode_socket).is_err());
                own.transition_data(PeerNativePhase::SocketMode,Some(0),false,bound_directory,mode_socket).unwrap();
                assert_eq!(own.phase,RemovalPeerOwnPhase::Published);
                assert_eq!(own.socket,Some(mode_socket));
                assert!(own.transition_data(PeerNativePhase::SocketMode,Some(0),false,bound_directory,mode_socket).is_err());
                assert_eq!(removal_peer_roster_entry_data(0,30,nix::libc::DT_REG,b"request.json",30,None),Ok(1));
                assert_eq!(removal_peer_roster_entry_data(1,21,nix::libc::DT_SOCK,b"s",30,Some(mode_socket)),Ok(3));
                assert_eq!(removal_peer_roster_entry_data(0,21,nix::libc::DT_SOCK,b"s",30,Some(mode_socket)),Ok(2));
                assert_eq!(removal_peer_roster_entry_data(2,30,nix::libc::DT_REG,b"request.json",30,Some(mode_socket)),Ok(3));
                for (seen,inode,kind,name,socket) in [
                    (0,21,nix::libc::DT_SOCK,&b"s"[..],None),
                    (0,0,nix::libc::DT_REG,&b"request.json"[..],None),
                    (0,99,nix::libc::DT_REG,&b"request.json"[..],None),
                    (1,30,nix::libc::DT_REG,&b"request.json"[..],None),
                    (3,21,nix::libc::DT_SOCK,&b"s"[..],Some(mode_socket)),
                    (0,21,nix::libc::DT_LNK,&b"s"[..],Some(mode_socket)),
                    (0,21,nix::libc::DT_REG,&b"s"[..],Some(mode_socket)),
                    (0,21,nix::libc::DT_SOCK,&b"extra"[..],Some(mode_socket))] {
                    assert!(removal_peer_roster_entry_data(seen,inode,kind,name,30,socket).is_err());
                }
                use native::install_producer::{SignatureResult,CurrentProductResult};
                // Actual production DATA predicates, never fake verifier
                // instances/current originals or a constructible capability.
                assert!(maintenance::removal_current_only_data(ActionData::SamePackageNoop,[true;2],false,true,true));
                for action in [ActionData::FreshInstall,ActionData::Update,ActionData::RestoreFixedApp] {
                    assert!(!maintenance::removal_current_only_data(action,[true;2],false,true,true));
                }
                for present in [[false,true],[true,false],[false,false]] {
                    assert!(!maintenance::removal_current_only_data(ActionData::SamePackageNoop,present,false,true,true));
                }
                for (intent,controls,current) in [(true,true,true),(false,false,true),(false,true,false)] {
                    assert!(!maintenance::removal_current_only_data(ActionData::SamePackageNoop,[true;2],intent,controls,current));
                }
                use native::install_producer::{ProducerCustody,ProducerOperation as Operation,CurrentProductRole as Role};
                let state=ProducerCustody { operation:Operation::DetachedSignature,phase:None,
                    cell:native::android_service_management::CellCustody::Consumed,references:[0;26],
                    entered:true,in_call:false,gate_entered:false,signature_matched:true,purpose_matched:None,
                    remove_signature_matched:false,remove_program_matched:false,failed:false,unknown:false,
                    calls:0,returned:0,first_failure:None };
                let states=[state,
                    ProducerCustody{operation:Operation::CurrentProduct(Role::EntryApp),signature_matched:false,purpose_matched:Some(Role::EntryApp),..state},
                    ProducerCustody{operation:Operation::CurrentProduct(Role::PayloadApp),signature_matched:false,purpose_matched:Some(Role::PayloadApp),..state},
                    ProducerCustody{operation:Operation::RemoveDetachedSignature,signature_matched:false,remove_signature_matched:true,..state},
                    ProducerCustody{operation:Operation::RemoveProgram,signature_matched:false,remove_program_matched:true,..state}];
                assert!(removal_native_admitted_data(true,true,[true;5],states));
                assert!(!removal_native_admitted_data(false,true,[true;5],states));
                assert!(!removal_native_admitted_data(true,false,[true;5],states));
                for i in 0..5 {
                    let mut closed=[true;5];closed[i]=false;
                    assert!(!removal_native_admitted_data(true,true,closed,states));
                    for bad in [ProducerCustody{failed:true,..states[i]},ProducerCustody{unknown:true,..states[i]},
                        ProducerCustody{in_call:true,..states[i]},ProducerCustody{gate_entered:true,..states[i]},
                        ProducerCustody{operation:states[(i+1)%5].operation,..states[i]},
                        ProducerCustody{signature_matched:false,purpose_matched:None,remove_signature_matched:false,remove_program_matched:false,..states[i]}] {
                        let mut changed=states;changed[i]=bad;
                        assert!(!removal_native_admitted_data(true,true,[true;5],changed));
                    }
                }
                use mobile_release_desktop::macos_install_maintenance::ReleaseBindingData;
                let source="1".repeat(40);let digest="2".repeat(64);
                let binding=ReleaseBindingData { profile:"unused",package_identifier:paths::PACKAGE_ID,bundle_identifier:paths::BUNDLE_ID,
                    package_version:paths::PACKAGE_VERSION,release:paths::RELEASE,source_commit:&source,
                    protocol_sha256:paths::PROTOCOL_SHA,runtime_manifest_sha256:&digest,inventory_sha256:&digest,
                    signing_policy_sha256:&digest,package_sha256:&digest };
                assert!(removal_source_binding_data(&binding,Some(&source),Some(&digest),&digest,&digest));
                for changed in [ReleaseBindingData{release:"legacy",..binding},ReleaseBindingData{package_version:"0",..binding},
                    ReleaseBindingData{source_commit:"different",..binding},ReleaseBindingData{protocol_sha256:"different",..binding},
                    ReleaseBindingData{runtime_manifest_sha256:"different",..binding}] {
                    assert!(!removal_source_binding_data(&changed,Some(&source),Some(&digest),&digest,&digest));
                }
                assert!(!removal_source_binding_data(&binding,None,Some(&digest),&digest,&digest));
                assert!(!removal_source_binding_data(&binding,Some(&source),None,&digest,&digest));
                assert!(!removal_source_binding_data(&binding,Some(&source),Some(&digest),&digest,"different"));
                // The shared wire -> fixed native comparison tuple is a real
                // protocol boundary. Test conversion without creating a peer,
                // cutoff, random identity or native verifier capability.
                assert_eq!(removal_hex_data::<16>(&"ff".repeat(16)),Ok([255;16]));
                for bad in ["00".repeat(16),"AA".repeat(16),"gg".repeat(16),"1".repeat(31),"1".repeat(33),"é".repeat(16)] {
                    assert!(removal_hex_data::<16>(&bad).is_err());
                }
                // Concrete retained state capacity consumes the same budget;
                // there is no second full-observation allowance or saturation.
                assert_eq!(removal_reobserve_budget_data(1024,transaction::STATE_LIMIT),Ok(1024+transaction::STATE_LIMIT as u64));
                assert!(removal_reobserve_budget_data(0,0).is_err());
                assert!(removal_reobserve_budget_data(0,transaction::STATE_LIMIT+1).is_err());
                assert!(removal_reobserve_budget_data(16*1024*1024,1).is_err());
                assert!(removal_reobserve_budget_data(u64::MAX,1).is_err());
                // Actual returned mkdir/file-entry effects alone may advance
                // directory metadata. Full mode/owner/inode/flags remain fixed;
                // no assumption about APFS directory link-count deltas is made.
                let directory=Identity { dev:1,ino:2,mode:0o40755,uid:0,gid:0,links:2,size:64,
                    mtime:1,mtime_ns:0,ctime:1,ctime_ns:0 };
                let changed=Identity { links:3,size:128,mtime:2,ctime:2,..directory };
                assert!(removal_parent_change_data(directory,0,directory,0,directory,0,false));
                assert!(removal_parent_change_data(directory,0,changed,0,changed,0,true));
                assert!(!removal_parent_change_data(directory,0,changed,0,changed,0,false));
                assert!(!removal_parent_change_data(directory,0,changed,0,directory,0,true));
                for unsafe_change in [Identity{dev:2,..changed},Identity{ino:3,..changed},
                    Identity{mode:0o40777,..changed},Identity{uid:1,..changed},Identity{gid:1,..changed},
                    Identity{mode:0o100755,..changed}] {
                    assert!(!removal_parent_change_data(directory,0,unsafe_change,0,unsafe_change,0,true));
                }
                assert!(!removal_parent_change_data(directory,0,changed,1,changed,1,true));
                assert!(!removal_parent_change_data(directory,0,changed,0,changed,1,true));
                assert!(removal_request_name_data(&format!("r-{}","1".repeat(32))));
                for bad in ["r-".into(),format!("r-{}","0".repeat(32)),format!("r-{}","A".repeat(32)),
                    format!("s-{}","1".repeat(32)),format!("r-{}","é".repeat(16)),"request.json".into()] {
                    assert!(!removal_request_name_data(&bad));
                }
                use mobile_release_desktop::macos_remove_protocol::{BindingData,BindingInputData,TargetData};
                for (target,release,native_target) in [(TargetData::Arm64,"macos26-arm64-1",native::removal_coordinator::RemovalTargetData::Arm64),
                    (TargetData::Intel,"macos26-x86_64-1",native::removal_coordinator::RemovalTargetData::Intel)] {
                    let request=BindingData::new_data(BindingInputData { request_id:&"1".repeat(32),root_nonce:&"2".repeat(32),
                        source_commit:&"3".repeat(40),release,target,remove_producer_sha256:&"4".repeat(64),
                        installed_producer_sha256:&"5".repeat(64),installed_inventory_sha256:&"6".repeat(64),
                        protocol_sha256:&"7".repeat(64),start:10,work:10+TOTAL-SETTLEMENT,hard:10+TOTAL }).unwrap();
                    let actual=removal_native_binding_data(&request).unwrap();let mut expected_release=[0;128];
                    expected_release[..release.len()].copy_from_slice(release.as_bytes());
                    assert_eq!(actual,native::removal_coordinator::RemovalChallengeData {
                        request_id:[0x11;16],root_nonce:[0x22;16],source:[0x33;20],target:native_target,
                        release:expected_release,release_len:release.len() as u8,remove_producer:[0x44;32],
                        installed_producer:[0x55;32],inventory:[0x66;32],protocol:[0x77;32],
                        start:10,work:10+TOTAL-SETTLEMENT,hard:10+TOTAL });
                }
                let signature=Some(SignatureResult::SignatureVerified);
                let purpose=Some(CurrentProductResult::PurposeVerified);
                assert!(producer_results_data(signature,purpose,purpose,true,true,[true;3]));
                for rejected in [None,Some(SignatureResult::Unavailable),Some(SignatureResult::Refused),Some(SignatureResult::Unknown)] {
                    assert!(!producer_results_data(rejected,purpose,purpose,true,true,[true;3]));
                }
                for rejected in [None,Some(CurrentProductResult::Unavailable),Some(CurrentProductResult::Refused),Some(CurrentProductResult::Unknown)] {
                    assert!(!producer_results_data(signature,rejected,purpose,true,true,[true;3]));
                    assert!(!producer_results_data(signature,purpose,rejected,true,true,[true;3]));
                }
                for index in 0..3 {
                    let mut closed=[true;3]; closed[index]=false;
                    assert!(!producer_results_data(signature,purpose,purpose,true,true,closed));
                }
                assert!(!producer_results_data(signature,purpose,purpose,false,true,[true;3]));
                assert!(!producer_results_data(signature,purpose,purpose,true,false,[true;3]));
                let invocation = "11111111111111111111111111111111"; let sha = "a".repeat(64);
                assert!(invocation_valid(invocation)); assert!(!invocation_valid(&"0".repeat(32)));
                assert_eq!(transaction::request_from_package_name_data("Install.pkg").unwrap(),None);
                assert_eq!(transaction::request_from_package_name_data(&format!("MobileReleaseKit-Request-{invocation}.pkg")).unwrap(),Some(invocation.into()));
                assert_eq!(transaction::export_name_data(invocation).unwrap(),format!("MobileReleaseKit-InstallerResult-v2-{invocation}.json"));
                for bad in ["../Install.pkg".into(),"Other.pkg".into(),
                    format!("MobileReleaseKit-Request-{}.pkg","0".repeat(32)),
                    format!("MobileReleaseKit-Request-{invocation}.pkg/extra")] {
                    assert!(transaction::request_from_package_name_data(&bad).is_err());
                }
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
                    runtime:"confirmed".into(),app:"confirmed".into(),timely:true,unknown:false,writes:1,bytes:1,reason:None,maintenance:None };
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
                for (action,state,runtime,app,writes) in [
                    (ActionData::FreshInstall,"installed","confirmed","confirmed",24_577),
                    (ActionData::Update,"installed","confirmed","confirmed",24_577),
                    (ActionData::SamePackageNoop,"same-package","not-attempted","not-attempted",0),
                    (ActionData::RestoreFixedApp,"restored-app","not-attempted","confirmed",17),
                ] {
                    let returned = PreExit { exit:0,state:state.into(),originals:true,payload:true,verified:true,
                        runtime:runtime.into(),app:app.into(),timely:true,unknown:false,writes,bytes:writes,reason:None,
                        maintenance:Some(MaintenanceReply { action,progress:"recorded".into(),state_published:true,
                            // This bounded frame does not confer StateData or
                            // package authority. The parent separately parses
                            // and reobserves the exact state after original wait.
                            state_bytes:Some("{}".into()),inverse:false }) };
                    let value = returned.data(invocation,&sha);
                    assert!(PreExit::parse(&value,invocation,&sha).is_ok(),"{state}");
                    for key in ["originalsClosed","payloadClosed","payloadVerified","withinOriginalDeadline"] {
                        let mut changed = value.clone(); changed[key] = json!(false);
                        assert!(PreExit::parse(&changed,invocation,&sha).is_err(),"{state}/{key}");
                    }
                    for (key,bad) in [("statePublished",json!(false)),("stateBytes",Value::Null),
                        ("progress",json!("refused")),("inverseStarted",json!(true)),("action",json!("uninstall")),
                        ("parentJoined",json!(true))] {
                        let mut changed = value.clone(); changed["maintenance"][key] = bad;
                        assert!(PreExit::parse(&changed,invocation,&sha).is_err(),"{state}/{key}");
                    }
                    let mut changed = value.clone(); changed["maintenance"]["stateBytes"] = json!("x".repeat(transaction::STATE_LIMIT+1));
                    assert!(PreExit::parse(&changed,invocation,&sha).is_err());
                    let mut changed = value.clone(); changed["payloadWriteBytes"] = json!(writes+1);
                    if writes == 0 { assert!(PreExit::parse(&changed,invocation,&sha).is_err()); }
                    else {
                        changed["payloadWriteBytes"] = json!(writes-1);
                        assert!(PreExit::parse(&changed,invocation,&sha).is_err());
                    }
                    let mut changed = value.clone(); changed["runtimePublication"] = json!(if runtime == "confirmed" { "not-attempted" } else { "confirmed" });
                    assert!(PreExit::parse(&changed,invocation,&sha).is_err());
                }
                let inverse = PreExit { exit:20,state:"inverse-recorded".into(),originals:true,payload:true,verified:true,
                    runtime:"confirmed".into(),app:"confirmed".into(),timely:true,unknown:false,writes:17,bytes:17,
                    reason:Some("other-original-refusal".into()),maintenance:Some(MaintenanceReply { action:ActionData::Update,
                        progress:"inverse-recorded".into(),state_published:true,state_bytes:Some("{}".into()),inverse:true }) };
                let value = inverse.data(invocation,&sha); assert!(PreExit::parse(&value,invocation,&sha).is_ok());
                for (key,bad) in [("exitCode",json!(0)),("withinOriginalDeadline",json!(false)),("unknown",json!(true))] {
                    let mut changed = value.clone(); changed[key] = bad;
                    assert!(PreExit::parse(&changed,invocation,&sha).is_err());
                }
            }
            #[test]
            fn original_join_requires_eof_closes_matching_return_and_timely_sources() {
                // Execute the same Parent reducers without inventing a native
                // verifier/peer/retirement capability or a filesystem effect.
                use removal_peer_native::{RemovalPeerCustody as PeerCustody,RemovalPeerRole as PeerRole,
                    RemovalPeerOperation as PeerOperation,RemovalOriginalData as PeerOriginal};
                use native::android_service_management::CellCustody;
                let peer_directory=PeerOriginal {device:1,inode:20,links:2,size:64,mode:0o40755,
                    modified_seconds:1,changed_seconds:1,..PeerOriginal::default()};
                let effects=RemovalPeerOwnEffects::new_data(peer_directory).unwrap();
                let peer=PeerCustody {role:PeerRole::Parent,cell:CellCustody::Owned,in_call:false,in_gate:false,
                    failed:false,unknown:false,first_failure:None,native_first_code:0,native_first_failure:0,
                    native_calls:40,native_returns:40,native_stage:4,frame_index:0,frame_pending:true,
                    frames_bytes:0,fds:[2;3],references:[2;24],peer_pid:42,peer_uid:501,peer_gid:20,
                    actual_exit_observed:false,native_closed:false,last_parent_monotonic:10,
                    request_directory:peer_directory,socket_name:PeerOriginal::default()};
                for index in 0..4 {
                    let begun=PeerCustody{frame_index:index,..peer};
                    assert!(removal_peer_begin_data(index,begun));
                    assert!(!removal_peer_complete_data(index,begun)); // BEGIN Ready is not a send.
                    let complete=PeerCustody{frame_index:index+1,frame_pending:false,frames_bytes:100,..begun};
                    assert!(removal_peer_complete_data(index,complete));
                    assert!(!removal_peer_begin_data(index,complete));
                    for bad in [PeerCustody{frame_pending:true,..complete},PeerCustody{frame_index:index,..complete},
                        PeerCustody{frames_bytes:4,..complete},PeerCustody{frames_bytes:4101,..complete},
                        PeerCustody{role:PeerRole::App,..complete}] {
                        assert!(!removal_peer_complete_data(index,bad));
                    }
                }
                let ack=PeerCustody{frame_index:4,frame_pending:false,frames_bytes:100,..peer};
                let mut ledger=RemovalPeerLocal::new(effects);
                ledger.observe(PeerCustody{frame_index:3,frames_bytes:0,..peer});
                assert!(!ledger.ack_complete);
                ledger.before_call_data(PeerOperation::PollFrame).unwrap();
                // Actual complete Ack remains latched after the later source
                // or clock failure. The next call still cannot query live code.
                ledger.observe(ack);ledger.note("later-work-cutoff");
                assert!(ledger.ack_complete);assert!(!ledger.exit_started);
                for operation in [PeerOperation::Source,PeerOperation::Open,PeerOperation::Connect,PeerOperation::Authenticate,
                    PeerOperation::BeginFrame,PeerOperation::PollFrame,PeerOperation::Recheck,PeerOperation::Close] {
                    assert!(ledger.before_call_data(operation).is_err());
                }
                ledger.before_call_data(PeerOperation::WaitExit).unwrap();
                assert!(ledger.exit_started);ledger.before_call_data(PeerOperation::WaitExit).unwrap();
                assert!(ledger.before_call_data(PeerOperation::Recheck).is_err());
                assert!(ledger.before_call_data(PeerOperation::BeginFrame).is_err());
                ledger.before_call_data(PeerOperation::Close).unwrap();
                let mut premature=RemovalPeerLocal::new(effects);
                premature.observe(peer);
                assert!(premature.before_call_data(PeerOperation::WaitExit).is_err());
                let mut first=RemovalPeerLocal::new(effects);
                first.observe(PeerCustody{failed:true,native_first_code:13,native_first_failure:17,..peer});
                first.note("later-parent-clock-veto");
                first.observe(PeerCustody{failed:true,unknown:true,native_first_code:13,native_first_failure:17,..peer});
                assert_eq!(first.native_first,Some((13,17)));
                assert_eq!(first.first,Some("removal-peer-native-refused"));
                let closed=PeerCustody{cell:CellCustody::Consumed,native_closed:true,fds:[4;3],references:[4;24],..ack};
                assert!(removal_peer_known_retired_data(true,closed));
                assert!(!removal_peer_known_retired_data(false,closed));
                for bad in [PeerCustody{cell:CellCustody::Owned,..closed},PeerCustody{in_call:true,..closed},
                    PeerCustody{in_gate:true,..closed},PeerCustody{fds:[4,5,4],..closed},
                    PeerCustody{references:[2;24],..closed}] {
                    assert!(!removal_peer_known_retired_data(true,bad));
                }
                // A later Unknown does not rewrite a known consuming return;
                // it still cannot supply the required successful native proof.
                assert!(removal_peer_known_retired_data(true,PeerCustody{unknown:true,..closed}));
                let absent=PeerCustody {cell:CellCustody::Absent,fds:[0;3],references:[0;24],frame_pending:false,..peer};
                assert!(removal_peer_known_retired_data(true,absent));
                let mut release=[0;128];let text=b"macos26-arm64-1";release[..text.len()].copy_from_slice(text);
                let binding=removal_peer_native::RemovalChallengeData {request_id:[1;16],root_nonce:[2;16],source:[3;20],
                    target:removal_peer_native::RemovalTargetData::Arm64,release,release_len:text.len() as u8,
                    remove_producer:[4;32],installed_producer:[5;32],inventory:[6;32],protocol:[7;32],
                    start:10,work:10+TOTAL-SETTLEMENT,hard:10+TOTAL};
                for custody in [absent,closed,PeerCustody{actual_exit_observed:true,..closed}] {
                    let scope=RemovalPeerScope {proof:None,preparation:Some(removal_protocol::PreparationData::NeverRegistered),
                        app_nonce:Some([8;16]),effects,first:None,native_first:None,custody:Some(custody),settled:true};
                    assert!(matches!(scope.into_completion(&binding),Err("removal-peer-success-proof-missing")));
                }
                // No actual PeerRetired is constructed here: known absence,
                // EOF/no-exit, or even copied exit=true are not capabilities.
                assert!(joined_data(true,true,true,true,Some(0),0,true,true,false));
                assert_eq!(completed_exit_data(Some(0),true,true,true,true,true,true,true,false),0);
                assert_eq!(completed_exit_data(Some(0),false,true,true,true,true,true,true,false),0); // Same-package.
                for missing in 0..6 {
                    let mut facts=[true;6]; facts[missing]=false;
                    assert_eq!(completed_exit_data(Some(0),true,facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],false),20);
                    assert_eq!(completed_exit_data(Some(0),false,facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],false),1);
                }
                assert_eq!(completed_exit_data(Some(0),true,true,true,true,true,true,true,true),20);
                assert_eq!(completed_exit_data(Some(1),false,true,true,true,true,true,true,false),1);
                assert_eq!(completed_exit_data(Some(20),true,true,true,true,true,true,true,false),20);
                assert_eq!(completed_exit_data(None,false,true,true,true,true,true,true,false),1);
                assert_eq!(completed_exit_data(Some(101),false,true,true,true,true,true,true,false),1);
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
    pub(super) fn run() -> i32 { worker::entry() }
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
                // Shared postinstall plumbing only; the third value is never opened or trusted here.
                check(args.len() == 3 && args[2].starts_with('/') && source_bound && table, "fixture-fixed-source-input-or-policy-table")?;
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
