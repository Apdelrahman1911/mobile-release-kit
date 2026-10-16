// Native convenience-bundle operations using the Installer's existing original
// descriptor book, clock, copier and exclusive rename. This module is private
// to macos_install; there is no new process owner or caller-selected target.
//
// Enrollment in current-state, recovery and removal census is deliberately a
// prerequisite for calling these operations. Merely compiling this adapter
// does not publish /Applications or report a fully installed application.
use super::*;
use mobile_release_desktop::macos_applications_launcher as launcher;
use installation_record::InventoryIndex;

pub(super) const WORK_NAME: &str = ".applications-launcher-v1";
const SOURCE_NAME: &str = "MobileReleaseKitLauncher.app";
const RETAINED_NAME: &str = "previous.app";

// A workspace belongs to the installed generation's original creation stage.
// The instance survives no-op and restore operations; no new root-level name
// or directory selected by scanning is introduced.
pub(super) struct Workspace {
    original: usize, stage: usize, instance: String,
    pub(super) retirement_attempted: bool, pub(super) retired: bool,
    pub(super) retirement_settled: bool,
}
impl Workspace {
    pub(super) fn create(book: &mut Install, prepared: &PreparedFresh,
        generation: &transaction::GenerationData) -> Result<Self> {
        Operation::mutation_ready(book)?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        let binding = generation.release_data().binding_data();
        check(root == prepared.destination && binding.release == paths::RELEASE
            && Some(binding.inventory_sha256) == option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256")
            && Some(binding.source_commit) == option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT")
            && Some(binding.runtime_manifest_sha256) == option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
            && format!("{:x}", Sha256::digest(&prepared.inventory_bytes)) == binding.inventory_sha256,
            "launcher-generation-binding")?;
        launcher::LauncherInventory::from_index(&prepared.inventory.index()?)?.ok_or("launcher-inventory-missing")?;
        let instance = generation.instance_data();
        check(worker::invocation_valid(instance), "launcher-generation-instance")?;
        let stage = book.open(Some(root), &format!(".install-{instance}"), true)?;
        book.protected(stage, true, Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_| "launcher-stage-attributes")?;
        // Existing leftovers are a recovery case, never adopted or overwritten
        // by ordinary create. The full census must authorize a resume first.
        let original = book.directory(stage, WORK_NAME, true, 0o700)?;
        let out = Self { original, stage, instance: instance.to_owned(),
            retirement_attempted: false, retired: false, retirement_settled: false };
        out.post(book)?;
        Ok(out)
    }
    // Only an already authenticated generation/inventory selects this stage.
    // No directory scanning, previous filename, or persisted success bit grants
    // authority. The caller must retain its original completed-package/history
    // admission; this method adds exact filesystem correspondence to that input.
    pub(super) fn admit(book: &mut Install, generation: &transaction::GenerationData,
        inventory_bytes: &[u8]) -> Result<Option<Self>> {
        check(book.gate.verified, "launcher-maintenance-required")?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        let binding = generation.release_data().binding_data();
        check(format!("{:x}", Sha256::digest(inventory_bytes)) == binding.inventory_sha256,
            "launcher-generation-binding")?;
        let inventory = Inventory::parse_for_release(inventory_bytes, binding.runtime_manifest_sha256, binding.release)?;
        launcher::LauncherInventory::from_index(&inventory.index()?)?.ok_or("launcher-inventory-missing")?;
        let instance = generation.instance_data();
        check(worker::invocation_valid(instance), "launcher-generation-instance")?;
        let stage = book.open(Some(root), &format!(".install-{instance}"), true)?;
        book.protected(stage, true, Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_| "launcher-stage-attributes")?;
        if let Err(Errno::ENOENT) = book.named(Some(stage), WORK_NAME) {
            book.check_name(stage, true)?;
            book.forward_close(stage, "launcher-stage-close")?;
            return Ok(None);
        }
        let original = book.open(Some(stage), WORK_NAME, true)?;
        let out = Self { original, stage, instance: instance.to_owned(),
            retirement_attempted: false, retired: false, retirement_settled: false };
        out.post(book)?;
        out.roster(book)?;
        Ok(Some(out))
    }

    fn roster(&self, book: &mut Install) -> Result<BTreeMap<String, u64>> {
        self.post(book)?;
        let before = Identity::of(&stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-stat")?);
        let actual = maintenance::roster_now(book, self.original)?;
        check(actual.len() <= 2 && actual.keys().all(|name| name == SOURCE_NAME || name == RETAINED_NAME),
            "launcher-workspace-roster")?;
        self.post(book)?;
        check(Identity::of(&stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-stat")?) == before,
            "launcher-workspace-changed")?;
        // This private directory is mutable by our recorded copy/move effects.
        // Its fresh, stable observation is not authority for any child bytes.
        book.originals[self.original].identity = Some(before);
        Ok(actual)
    }

    // Successful operations leave the old exact phase-directory census intact.
    // Only this held EMPTY workspace is removed. Preserve returned effects even
    // if a following check/close fails; there is no name-based cleanup retry.
    pub(super) fn retire_empty(&mut self, book: &mut Install) -> Result<()> {
        check(!self.retirement_attempted && !self.retired, "launcher-workspace-retirement-once")?;
        Operation::mutation_ready(book)?;
        check(self.roster(book)?.is_empty(), "launcher-workspace-not-empty")?;
        let before = stat::fstat(book.fd(self.stage)?).map_err(|_| "launcher-stage-stat")?;
        let mut remaining = maintenance::roster_now(book, self.stage)?;
        check(remaining.remove(WORK_NAME) == Some(book.identity(self.original)?.ino),
            "launcher-workspace-name")?;
        book.persist(self.original, false)?;
        book.check_name(self.original, true)?;
        let expected = book.identity(self.original)?;
        self.retirement_attempted = true;
        match unistd::unlinkat(book.fd(self.stage)?, WORK_NAME, unistd::UnlinkatFlags::RemoveDir) {
            Ok(()) => self.retired = true,
            Err(_) => { book.unknown = true; return Err("launcher-workspace-unlink-unknown"); }
        }
        book.clock()?;
        book.absent(self.stage, WORK_NAME)?;
        let actual = stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-unlinked-stat")?;
        check(expected.same_object(Identity::of(&actual)) && expected.mode == u32::from(actual.st_mode)
            && actual.st_flags == 0, "launcher-workspace-unlinked-original")?;
        refresh_removed_parent(book, self.stage, before, &remaining)?;
        book.forward_close(self.original, "launcher-workspace-close")?;
        book.persist(self.stage, false)?;
        book.check_name(self.stage, true)?;
        book.forward_close(self.stage, "launcher-stage-close")?;
        self.retirement_settled = true;
        Ok(())
    }

    fn post(&self, book: &Install) -> Result<()> {
        check(!self.retirement_attempted && !self.retired, "launcher-workspace-retired")?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        check(book.originals[self.stage].parent == Some(root)
            && book.originals[self.stage].name == format!(".install-{}", self.instance)
            && book.originals[self.original].parent == Some(self.stage)
            && book.originals[self.original].name == WORK_NAME, "launcher-workspace-binding")?;
        book.check_name(root, false)?;
        book.protected(root, true, Some(0o755))?;
        for original in [self.stage, self.original] {
            book.check_name(original, false)?;
            book.protected(original, true, Some(0o700))?;
            check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-workspace-stat")?.st_flags == 0,
                "launcher-workspace-flags")?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-workspace-attributes")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Returned { NotAttempted, Attempting, Refused, Published, Quarantined, Unknown }

// Returned effects live in the caller's original book-owned operation. An
// error after rename does not erase the syscall effect or allow another try.
pub(super) struct Operation {
    applications: usize,
    system_root: usize,
    bundle: Option<usize>,
    pub(super) returned: Returned,
    pub(super) verified: bool,
}
impl Operation {
    pub(super) fn open(book: &mut Install) -> Result<Self> {
        book.clock()?;
        check(book.gate.verified && book.gate.parent.is_some(), "launcher-maintenance-required")?;
        let system_root = book.open(None, "/", true)?;
        book.protected_as(system_root, true, None, AclRole::SystemRoot)?;
        let applications = book.open(Some(system_root), "Applications", true)?;
        let out = Self { applications, system_root, bundle: None, returned: Returned::NotAttempted, verified: false };
        out.parent_post(book)?;
        Ok(out)
    }

    fn parent_post(&self, book: &Install) -> Result<()> {
        book.clock()?;
        book.check_name(self.system_root, false)?;
        book.protected_as(self.system_root, true, None, AclRole::SystemRoot)?;
        book.check_name(self.applications, false)?;
        let value = stat::fstat(book.fd(self.applications)?).map_err(|_| "launcher-parent-stat")?;
        // /Applications is an ordinary shared convenience namespace. Unlike
        // the runtime root it may be admin-group writable and have an Apple
        // ACL. Do not chmod it, pretend its roster authenticates a source, or
        // relax the existing protection policy for any protected payload.
        check(value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits()
            && value.st_uid == 0 && value.st_mode & 0o002 == 0,
            "launcher-parent-policy")?;
        let fs = statfs::fstatfs(book.fd(self.applications)?).map_err(|_| "launcher-parent-mount")?;
        check(fs.filesystem_type_name() == "apfs" && fs.flags().contains(MntFlags::MNT_LOCAL)
            && !fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP),
            "launcher-parent-mount")?;
        book.clock()
    }

    fn mutation_ready(book: &Install) -> Result<()> {
        book.clock()?;
        check(book.gate.verified && (book.gate.exclusive_acquired
            || book.worker_stderr_is_gate && book.worker_go_eof
                && book.worker_deadline.is_some() && !book.gate.lock_attempted),
            "launcher-exclusive-maintenance-required")?;
        book.registration_ready()
    }

    pub(super) fn absent(&self, book: &Install) -> Result<bool> {
        self.parent_post(book)?;
        let result = match book.named(Some(self.applications), launcher::APPLICATIONS_NAME) {
            Err(Errno::ENOENT) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err("launcher-observation-refused"),
        };
        self.parent_post(book)?;
        result
    }

    /// Exact authenticated inventory only. Unknown or modified bundles refuse;
    /// no signature-only approximation or name-based replacement is allowed.
    pub(super) fn hold_matching(&mut self, book: &mut Install, expected: &InventoryIndex<'_>) -> Result<()> {
        check(self.bundle.is_none() && self.returned == Returned::NotAttempted,
            "launcher-operation-once")?;
        launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        self.parent_post(book)?;
        let bundle = book.open(Some(self.applications), launcher::APPLICATIONS_NAME, true)?;
        // Store the exact original before any fallible read can return.
        self.bundle = Some(bundle);
        maintenance::audit_tree(book, bundle, launcher::BUNDLE, expected, 0)?;
        self.parent_post(book)?;
        book.check_name(bundle, true)
    }

    /// Copy from the completed package into a source-selected protected
    /// workspace. Never write a build/staging tree beneath /Applications.
    pub(super) fn stage(book: &mut Install, prepared: &PreparedFresh, workspace: &Workspace) -> Result<usize> {
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        let indexed = prepared.inventory.index()?;
        launcher::LauncherInventory::from_index(&indexed)?.ok_or("launcher-inventory-missing")?;
        check(book.gate.parent == Some(prepared.destination), "launcher-source-destination")?;
        let mut current = prepared.input;
        let mut opened = Vec::with_capacity(3);
        for name in ["app", "Contents", "Helpers"] {
            let child = book.open(Some(current), name, true)?;
            opened.push(child);
            book.protected(child, true, Some(0o555))?;
            native::no_xattrs(book.fd(child)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
            current = child;
        }
        book.absent(workspace.original, SOURCE_NAME)?;
        let bundle = book.copy_tree(launcher::BUNDLE, current, workspace.original, &indexed.files, &indexed.directories, 0)?;
        for original in opened.into_iter().rev() {
            book.check_name(original, true)?;
            book.forward_close(original, "launcher-source-close")?;
        }
        book.check_name(prepared.input, true)?;
        workspace.post(book)?;
        Ok(bundle)
    }

    pub(super) fn publish(&mut self, book: &mut Install, workspace: &Workspace, staged: usize,
        expected: &InventoryIndex<'_>) -> Result<()> {
        check(self.returned == Returned::NotAttempted && self.bundle.is_none(), "launcher-operation-once")?;
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        self.parent_post(book)?;
        check(book.originals[staged].parent == Some(workspace.original)
            && book.originals[staged].name == SOURCE_NAME, "launcher-staged-original")?;
        launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        maintenance::audit_tree(book, staged, launcher::BUNDLE, expected, 0)?;
        book.absent(self.applications, launcher::APPLICATIONS_NAME)?;
        check(book.identity(workspace.original)?.dev == book.identity(self.applications)?.dev, "launcher-filesystem")?;
        book.clock()?;
        // No overwrite-capable primitive, filesystem fallback or path retry.
        self.returned = Returned::Attempting;
        let result = native::publish_directory(book.fd(workspace.original)?.as_fd(), SOURCE_NAME,
            book.fd(self.applications)?.as_fd(), launcher::APPLICATIONS_NAME);
        match result {
            Ok(()) => self.returned = Returned::Published,
            Err(error) => {
                self.returned = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                    else { book.unknown = true; Returned::Unknown };
                return Err("launcher-publication-refused-or-unknown");
            }
        }
        self.bundle = Some(staged);
        maintenance::rebind_renamed(book, staged, self.applications, launcher::APPLICATIONS_NAME)?;
        book.absent(workspace.original, SOURCE_NAME)?;
        maintenance::audit_tree(book, staged, launcher::BUNDLE, expected, 0)?;
        book.persist(workspace.original, false)?;
        book.persist(self.applications, false)?;
        self.parent_post(book)?;
        book.check_name(staged, true)?;
        self.verified = true;
        Ok(())
    }

    /// Withdraw only the held matching bundle, retaining it under protection.
    /// A shared-parent race is rechecked AFTER the exclusive move. On mismatch
    /// retain the moved entry untouched: never delete it or overwrite a new
    /// Applications occupant in a guessed rollback.
    pub(super) fn quarantine(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>) -> Result<usize> {
        check(self.returned == Returned::NotAttempted, "launcher-operation-once")?;
        let bundle = self.bundle.ok_or("launcher-original-missing")?;
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        self.parent_post(book)?;
        check(book.originals[bundle].parent == Some(self.applications)
            && book.originals[bundle].name == launcher::APPLICATIONS_NAME, "launcher-original-binding")?;
        maintenance::audit_tree(book, bundle, launcher::BUNDLE, expected, 0)?;
        book.check_name(bundle, true)?;
        book.absent(workspace.original, RETAINED_NAME)?;
        check(book.identity(workspace.original)?.dev == book.identity(self.applications)?.dev, "launcher-filesystem")?;
        book.clock()?;
        self.returned = Returned::Attempting;
        let result = native::publish_directory(book.fd(self.applications)?.as_fd(), launcher::APPLICATIONS_NAME,
            book.fd(workspace.original)?.as_fd(), RETAINED_NAME);
        match result {
            Ok(()) => self.returned = Returned::Quarantined,
            Err(error) => {
                self.returned = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                    else { book.unknown = true; Returned::Unknown };
                return Err("launcher-withdrawal-refused-or-unknown");
            }
        }
        maintenance::rebind_renamed(book, bundle, workspace.original, RETAINED_NAME)?;
        maintenance::audit_tree(book, bundle, launcher::BUNDLE, expected, 0)?;
        // If another user placed an entry after the move, absence refuses and
        // the caller cannot publish over it. Our retained bundle stays intact.
        book.absent(self.applications, launcher::APPLICATIONS_NAME)?;
        book.persist(self.applications, false)?;
        book.persist(workspace.original, false)?;
        self.parent_post(book)?;
        self.verified = true;
        Ok(bundle)
    }
}

// At most five signed leaves and five directories, never a general recursive
// deletion API. Each original is retained before an unlink can be entered.
struct RetiredNode {
    original: usize, parent: usize, name: String, directory: bool,
    size: u64, digest: String, attempted: bool, removed: bool,
}
pub(super) struct Retirement {
    nodes: Vec<RetiredNode>, prepared: bool, entered: bool, root_name: &'static str,
    pub(super) first_failure: Option<&'static str>,
    pub(super) completed: bool,
}
impl Retirement {
    pub(super) fn new() -> Self {
        Self { nodes: Vec::with_capacity(10), prepared: false, entered: false, root_name: RETAINED_NAME,
            first_failure: None, completed: false }
    }

    // The caller stores `self` before calling prepare, so failure never loses
    // the exact attempted operation. Only a verified quarantined bundle enters.
    pub(super) fn prepare(&mut self, book: &mut Install, operation: &Operation,
        workspace: &Workspace, expected: &InventoryIndex<'_>) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        let result = self.prepare_inner(book, operation, workspace, expected);
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }
    fn prepare_inner(&mut self, book: &mut Install, operation: &Operation,
        workspace: &Workspace, expected: &InventoryIndex<'_>) -> Result<()> {
        Operation::mutation_ready(book)?;
        workspace.post(book)?;
        check(operation.returned == Returned::Quarantined && operation.verified,
            "launcher-retirement-quarantine")?;
        let bundle = operation.bundle.ok_or("launcher-original-missing")?;
        check(book.originals[bundle].parent == Some(workspace.original)
            && book.originals[bundle].name == RETAINED_NAME, "launcher-retirement-original")?;
        let selected = launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        // Ten held originals + bounded fresh roster readers; no new quota or
        // credit for a merely planned future close is introduced.
        let external = book.removal_live_reserved + if book.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 };
        check(book.originals.iter().filter(|r| r.fd.is_some()).count() + external + 12 <= 96
            && book.originals.len().checked_add(60).is_some_and(|n| n <= 24576), "launcher-retirement-budget")?;
        maintenance::audit_tree(book, bundle, launcher::BUNDLE, expected, 0)?;
        let mut directories = BTreeMap::new();
        directories.insert(String::new(), bundle);
        self.nodes.push(RetiredNode { original: bundle, parent: workspace.original,
            name: RETAINED_NAME.into(), directory: true, size: 0, digest: String::new(), attempted: false, removed: false });
        for path in ["Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
            let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
            let parent = *directories.get(parent_path).ok_or("launcher-retirement-parent")?;
            let original = book.open(Some(parent), name, true)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: true,
                size: 0, digest: String::new(), attempted: false, removed: false });
            book.protected(original, true, Some(0o555))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            directories.insert(path.into(), original);
        }
        for entry in selected.entries().iter().copied().chain(selected.ticket()) {
            let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
                .ok_or("launcher-retirement-file")?;
            let (parent_path, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
            let parent = *directories.get(parent_path).ok_or("launcher-retirement-parent")?;
            let original = book.open(Some(parent), name, false)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: false,
                size: entry.size, digest: entry.sha256.clone(), attempted: false, removed: false });
            book.protected(original, false, Some(if entry.executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
        }
        check(self.nodes.len() <= 10, "launcher-retirement-bound")?;
        workspace.post(book)?;
        self.prepared = true;
        Ok(())
    }

    // Resume an interrupted retirement from a protected generation workspace.
    // Only absent subsets of the EXACT authenticated signed bundle are allowed:
    // surviving files still require full original bytes/hash and sealed mode.
    // Caller stores this ledger first and independently selects the authorized
    // current/predecessor inventory; no persisted success claim is imported.
    pub(super) fn prepare_resumed(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        let result = self.capture_remaining(book, workspace, expected, None);
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }

    // Remove only an interrupted copy of the authenticated NEW source. A 0600
    // unsealed file must be an exact bounded prefix of the original signed file;
    // sealed survivors must be complete. Nothing is accepted just for its name.
    pub(super) fn prepare_staged_copy(&mut self, book: &mut Install, workspace: &Workspace,
        prepared: &PreparedFresh) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        self.root_name = SOURCE_NAME;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(book.gate.parent == Some(prepared.destination), "launcher-source-destination")?;
            let index = prepared.inventory.index()?;
            launcher::LauncherInventory::from_index(&index)?.ok_or("launcher-inventory-missing")?;
            let mut source = prepared.input;
            let mut opened = Vec::with_capacity(4);
            for name in ["app", "Contents", "Helpers", SOURCE_NAME] {
                let next = book.open(Some(source), name, true)?;
                opened.push(next);
                book.protected(next, true, Some(0o555))?;
                native::no_xattrs(book.fd(next)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
                source = next;
            }
            self.capture_remaining(book, workspace, &index, Some(source))?;
            for original in opened.into_iter().rev() {
                book.check_name(original, true)?;
                book.forward_close(original, "launcher-source-close")?;
            }
            book.check_name(prepared.input, true)
        })();
        // Do not leave prepared=true if source POST or original close refused.
        if let Err(error) = result { self.prepared = false; self.first_failure = Some(error); }
        result
    }

    fn capture_remaining(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>, source: Option<usize>) -> Result<()> {
        Operation::mutation_ready(book)?;
        let selected = launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        let top = workspace.roster(book)?;
        // A simultaneous staged new bundle requires publication/recovery
        // selection first; do not erase a retained predecessor preemptively.
        let other_name = if source.is_some() { RETAINED_NAME } else { SOURCE_NAME };
        check(!top.contains_key(other_name), "launcher-recovery-other-bundle-present")?;
        let Some(inode) = top.get(self.root_name).copied() else {
            self.prepared = true;
            return Ok(());
        };
        let external = book.removal_live_reserved + if book.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 };
        check(book.originals.iter().filter(|r| r.fd.is_some()).count() + external + 16 <= 96
            && book.originals.len().checked_add(100).is_some_and(|n| n <= 24576), "launcher-retirement-budget")?;
        let children = signed_children(&selected)?;
        let bundle = book.open(Some(workspace.original), self.root_name, true)?;
        self.nodes.push(RetiredNode { original: bundle, parent: workspace.original, name: self.root_name.into(),
            directory: true, size: 0, digest: String::new(), attempted: false, removed: false });
        check(book.identity(bundle)?.ino == inode, "launcher-recovery-original")?;
        let mut directories = BTreeMap::new();
        directories.insert(String::new(), bundle);
        let mut rosters = BTreeMap::new();
        for path in ["", "Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
            let directory = if path.is_empty() { bundle } else {
                let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
                let Some(parent) = directories.get(parent_path).copied() else { continue; };
                let roster: &BTreeMap<String, u64> = rosters.get(parent_path).ok_or("launcher-recovery-parent")?;
                let Some(inode) = roster.get(name).copied() else { continue; };
                let original = book.open(Some(parent), name, true)?;
                self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: true,
                    size: 0, digest: String::new(), attempted: false, removed: false });
                check(book.identity(original)?.ino == inode, "launcher-recovery-original")?;
                directories.insert(path.to_owned(), original);
                original
            };
            let mode = book.identity(directory)?.mode & 0o7777;
            check(mode == 0o555 || source.is_some() && mode == 0o700, "launcher-recovery-directory-mode")?;
            book.protected(directory, true, Some(mode))?;
            native::no_xattrs(book.fd(directory)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            check(stat::fstat(book.fd(directory)?).map_err(|_| "launcher-recovery-stat")?.st_flags == 0,
                "launcher-recovery-flags")?;
            let actual = maintenance::roster_now(book, directory)?;
            check(actual.keys().all(|name| children.get(path).is_some_and(|names| names.contains(name))),
                "launcher-recovery-unknown-child")?;
            rosters.insert(path.to_owned(), actual);
        }
        for entry in selected.entries().iter().copied().chain(selected.ticket()) {
            let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
                .ok_or("launcher-retirement-file")?;
            let (parent_path, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
            let Some(parent) = directories.get(parent_path).copied() else { continue; };
            let Some(inode) = rosters.get(parent_path).and_then(|row| row.get(name)).copied() else { continue; };
            let original = book.open(Some(parent), name, false)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: false,
                size: entry.size, digest: entry.sha256.clone(), attempted: false, removed: false });
            check(book.identity(original)?.ino == inode, "launcher-recovery-original")?;
            let actual = book.identity(original)?;
            let mode = actual.mode & 0o7777;
            let partial = source.is_some() && mode == 0o600;
            check(partial || mode == if entry.executable { 0o555 } else { 0o444 }, "launcher-recovery-file-mode")?;
            check(actual.size >= 0 && actual.size as u64 <= entry.size
                && (partial || actual.size as u64 == entry.size), "launcher-recovery-file-size")?;
            book.protected(original, false, Some(mode))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-recovery-stat")?.st_flags == 0,
                "launcher-recovery-flags")?;
            let digest = if let Some(source) = source {
                source_prefix(book, source, relative, original, actual.size as u64, entry)?
            } else {
                let digest = hash_at(book, original, entry.size)?;
                check(digest == entry.sha256, "launcher-recovery-file-hash")?;
                digest
            };
            let node = self.nodes.last_mut().ok_or("launcher-recovery-node")?;
            node.size = actual.size as u64;
            node.digest = digest;
        }
        // Exact first/second snapshots and retained originals, not a caller's
        // reconstructed namespace. Pread above leaves every file at offset zero
        // so run() genuinely rechecks its bytes immediately before unlink.
        for (path, directory) in &directories {
            check(maintenance::roster_now(book, *directory)? == rosters[path], "launcher-recovery-roster-changed")?;
            book.check_name(*directory, true)?;
        }
        for node in &self.nodes { book.check_name(node.original, true)?; }
        check(self.nodes.len() <= 10 && workspace.roster(book)? == top, "launcher-recovery-roster-changed")?;
        self.prepared = true;
        Ok(())
    }

    pub(super) fn run(&mut self, book: &mut Install, workspace: &Workspace) -> Result<()> {
        check(self.prepared && self.first_failure.is_none() && !self.completed,
            "launcher-retirement-not-ready")?;
        let result = (|| {
            // Leaves were appended after directories. Reverse order deletes
            // every leaf, then deepest known directories, then the bundle root.
            for slot in (0..self.nodes.len()).rev() { self.unlink(book, workspace, slot)?; }
            check(self.nodes.iter().all(|node| node.removed && node.attempted
                && book.originals[node.original].state == State::Closed
                && book.originals[node.original].fd.is_none()), "launcher-retirement-finality")?;
            book.absent(workspace.original, self.root_name)?;
            workspace.post(book)?;
            book.persist(workspace.original, false)?;
            book.clock()?;
            self.completed = true;
            Ok(())
        })();
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }

    fn unlink(&mut self, book: &mut Install, workspace: &Workspace, slot: usize) -> Result<()> {
        Operation::mutation_ready(book)?;
        workspace.post(book)?;
        let node = &self.nodes[slot];
        check(!node.attempted && !node.removed, "launcher-retirement-node-once")?;
        let (original, parent, name, directory) = (node.original, node.parent, node.name.clone(), node.directory);
        check(book.originals[original].parent == Some(parent) && book.originals[original].name == name,
            "launcher-retirement-node-original")?;
        book.check_name(original, true)?;
        let before = stat::fstat(book.fd(parent)?).map_err(|_| "launcher-retirement-parent-stat")?;
        let mut remaining = maintenance::roster_now(book, parent)?;
        check(remaining.remove(&name) == Some(book.identity(original)?.ino), "launcher-retirement-name")?;
        if directory {
            check(self.nodes.iter().filter(|child| child.parent == original).all(|child| child.removed),
                "launcher-retirement-children")?;
            check(maintenance::roster_now(book, original)?.is_empty(), "launcher-retirement-not-empty")?;
            book.persist(original, false)?;
        } else {
            check(book.read(original, node.size, false)?.0 == node.digest, "launcher-retirement-file-hash")?;
        }
        let expected = book.identity(original)?;
        check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-retirement-node-stat")?.st_flags == 0
            && before.st_flags == 0, "launcher-retirement-node-flags")?;
        native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
        book.check_name(original, true)?;
        book.clock()?;
        self.nodes[slot].attempted = true;
        let result = unistd::unlinkat(book.fd(parent)?, name.as_str(),
            if directory { unistd::UnlinkatFlags::RemoveDir } else { unistd::UnlinkatFlags::NoRemoveDir });
        match result {
            Ok(()) => self.nodes[slot].removed = true,
            Err(_) => { book.unknown = true; return Err("launcher-retirement-unlink-unknown"); }
        }
        book.clock()?;
        book.absent(parent, &name)?;
        let actual = stat::fstat(book.fd(original)?).map_err(|_| "launcher-retirement-unlinked-stat")?;
        check(expected.dev == i64::from(actual.st_dev) && expected.ino == actual.st_ino
            && expected.mode == u32::from(actual.st_mode) && expected.uid == actual.st_uid
            && expected.gid == actual.st_gid && actual.st_flags == 0, "launcher-retirement-unlinked-original")?;
        refresh_removed_parent(book, parent, before, &remaining)?;
        book.forward_close(original, "launcher-retirement-close")?;
        book.persist(parent, false)?;
        workspace.post(book)
    }
}

// Shared by bundle-leaf and empty-workspace retirement. Only the exact parent
// of an actually successful single-name unlink may refresh its original aliases.
fn refresh_removed_parent(book: &mut Install, parent: usize, before: FileStat,
    remaining: &BTreeMap<String, u64>) -> Result<()> {
        let changed = stat::fstat(book.fd(parent)?).map_err(|_| "launcher-retirement-parent-stat")?;
        let named = book.named(book.originals[parent].parent, &book.originals[parent].name)
            .map_err(|_| "launcher-retirement-parent-name")?;
        check(worker::removal_payload_parent_change_data(Identity::of(&before), before.st_flags,
            Identity::of(&changed), changed.st_flags, Identity::of(&named), named.st_flags),
            "launcher-retirement-parent-changed")?;
        check(maintenance::roster_now(book, parent)? == *remaining, "launcher-retirement-remaining-roster")?;
        // Refresh only aliases of this exact parent after its independently
        // checked own single-name removal. Other original baselines stay exact.
        for index in 0..book.originals.len() {
            if book.originals[index].fd.is_none() { continue; }
            let identity = book.identity(index)?;
            if identity.dev == i64::from(before.st_dev) && identity.ino == before.st_ino {
                let held = stat::fstat(book.fd(index)?).map_err(|_| "launcher-retirement-parent-stat")?;
                let alias_name = book.named(book.originals[index].parent, &book.originals[index].name)
                    .map_err(|_| "launcher-retirement-alias-name")?;
                check(worker::removal_payload_parent_change_data(identity, 0, Identity::of(&held), held.st_flags,
                    Identity::of(&alias_name), alias_name.st_flags)
                    && Identity::of(&held) == Identity::of(&changed), "launcher-retirement-alias")?;
                book.originals[index].identity = Some(Identity::of(&changed));
            }
        }
    Ok(())
}

// A fixed signed layout, not a generic filesystem deletion grammar. Optional
// stapled ticket is nominated by the same authenticated inventory as the four
// mandatory leaves; unknown additions never become removable.
fn signed_children(selected: &launcher::LauncherInventory<'_>) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in ["", "Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
        children.entry(path.into()).or_default();
        if !path.is_empty() {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            children.entry(parent.into()).or_default().insert(name.into());
        }
    }
    for entry in selected.entries().iter().copied().chain(selected.ticket()) {
        let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
            .ok_or("launcher-retirement-file")?;
        let (parent, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
        check(children.get_mut(parent).ok_or("launcher-retirement-parent")?.insert(name.into()),
            "launcher-retirement-duplicate")?;
    }
    Ok(children)
}

fn hash_at(book: &Install, original: usize, size: u64) -> Result<String> {
    check(size <= launcher::LIMITS[0] && book.identity(original)?.size >= 0
        && book.identity(original)?.size as u64 == size, "launcher-recovery-size")?;
    book.check_name(original, true)?;
    let mut buffer = [0u8; 65536];
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    while offset < size {
        book.clock()?;
        let take = usize::try_from((size-offset).min(buffer.len() as u64)).map_err(|_| "launcher-recovery-size")?;
        let count = nix::sys::uio::pread(book.fd(original)?, &mut buffer[..take], offset as i64)
            .map_err(|_| "launcher-recovery-read")?;
        check(count > 0 && count <= take, "launcher-recovery-read")?;
        offset += count as u64;
        digest.update(&buffer[..count]);
    }
    book.clock()?;
    check(nix::sys::uio::pread(book.fd(original)?, &mut buffer[..1], offset as i64)
        .map_err(|_| "launcher-recovery-read")? == 0, "launcher-recovery-eof")?;
    book.check_name(original, true)?;
    Ok(format!("{:x}", digest.finalize()))
}

// Full source hash precedes byte-prefix comparison. Positional reads retain
// original offsets and identity; cleanup never relies on a hash of an unknown
// partial file or treats zero-length/unsealed data as a complete signed asset.
fn source_prefix(book: &mut Install, source_root: usize, relative: &str,
    target: usize, size: u64, entry: &Entry) -> Result<String> {
    let parts: Vec<&str> = relative.split('/').collect();
    check((2..=3).contains(&parts.len()) && size <= entry.size, "launcher-source-prefix-path")?;
    let mut opened = Vec::with_capacity(3);
    let mut parent = source_root;
    for part in &parts[..parts.len()-1] {
        let next = book.open(Some(parent), part, true)?;
        opened.push(next);
        book.protected(next, true, Some(0o555))?;
        native::no_xattrs(book.fd(next)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
        parent = next;
    }
    let source = book.open(Some(parent), parts[parts.len()-1], false)?;
    opened.push(source);
    book.protected(source, false, Some(if entry.executable { 0o555 } else { 0o444 }))?;
    native::no_xattrs(book.fd(source)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
    check(hash_at(book, source, entry.size)? == entry.sha256, "launcher-source-file-hash")?;
    let digest = prefix_hash(size,
        |at, buffer| nix::sys::uio::pread(book.fd(source)?, buffer, at as i64).map_err(|_| "launcher-prefix-read"),
        |at, buffer| nix::sys::uio::pread(book.fd(target)?, buffer, at as i64).map_err(|_| "launcher-prefix-read"),
        || book.clock())?;
    book.check_name(target, true)?;
    for original in opened.into_iter().rev() {
        book.check_name(original, true)?;
        book.forward_close(original, "launcher-source-close")?;
    }
    book.check_name(source_root, true)?;
    Ok(digest)
}

// Shared actual byte-comparison loop; reader ports make short/error/late reads
// testable without privileged filesystem actions or a second deletion engine.
fn prefix_hash(size: u64,
    mut read_source: impl FnMut(u64, &mut [u8]) -> Result<usize>,
    mut read_target: impl FnMut(u64, &mut [u8]) -> Result<usize>,
    mut tick: impl FnMut() -> Result<()>) -> Result<String> {
    check(size <= launcher::LIMITS[0], "launcher-prefix-size")?;
    let mut source_buffer = [0u8; 65536];
    let mut target_buffer = [0u8; 65536];
    let mut offset = 0u64;
    let mut digest = Sha256::new();
    while offset < size {
        tick()?;
        let take = usize::try_from((size-offset).min(source_buffer.len() as u64)).map_err(|_| "launcher-prefix-size")?;
        // Short reads are allowed only with equal positive progress. Both
        // regular-file originals are bounded and checked again below.
        let target_count = read_target(offset, &mut target_buffer[..take])?;
        check(target_count > 0 && target_count <= take, "launcher-prefix-read")?;
        let mut source_count = 0usize;
        while source_count < target_count {
            tick()?;
            let count = read_source(offset + source_count as u64, &mut source_buffer[source_count..target_count])?;
            check(count > 0 && count <= target_count-source_count, "launcher-prefix-read")?;
            source_count += count;
        }
        check(source_buffer[..target_count] == target_buffer[..target_count], "launcher-prefix-mismatch")?;
        digest.update(&target_buffer[..target_count]);
        offset += target_count as u64;
    }
    tick()?;
    check(read_target(offset, &mut target_buffer[..1])? == 0, "launcher-prefix-eof")?;
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_bytes(bytes: &[u8], at: u64, output: &mut [u8], limit: usize) -> Result<usize> {
        let at = usize::try_from(at).map_err(|_| "test-offset")?;
        if at >= bytes.len() { return Ok(0); }
        let count = output.len().min(limit).min(bytes.len()-at);
        output[..count].copy_from_slice(&bytes[at..at+count]);
        Ok(count)
    }

    #[test]
    fn signed_prefix_comparison_handles_short_reads_and_rejects_foreign_or_extra_bytes() {
        let source: Vec<u8> = (0..65539).map(|n| (n % 251) as u8).collect();
        for length in [0, 3, 65535, 65536, 65539] {
            let target = &source[..length];
            let hash = prefix_hash(length as u64,
                |at, out| read_bytes(&source, at, out, 997),
                |at, out| read_bytes(target, at, out, 4001), || Ok(())).unwrap();
            assert_eq!(hash, format!("{:x}", Sha256::digest(target)));
        }
        let mut changed = source.clone(); changed[65536] ^= 1;
        assert_eq!(prefix_hash(source.len() as u64,
            |at, out| read_bytes(&source, at, out, 997),
            |at, out| read_bytes(&changed, at, out, 4001), || Ok(())), Err("launcher-prefix-mismatch"));
        assert_eq!(prefix_hash(3, |at, out| read_bytes(&source, at, out, 1),
            |at, out| read_bytes(&source[..4], at, out, 1), || Ok(())), Err("launcher-prefix-eof"));
        assert_eq!(prefix_hash(4, |at, out| read_bytes(&source, at, out, 1),
            |at, out| read_bytes(&source[..3], at, out, 1), || Ok(())), Err("launcher-prefix-read"));
        assert_eq!(prefix_hash(4, |at, out| read_bytes(&source[..3], at, out, 1),
            |at, out| read_bytes(&source[..4], at, out, 1), || Ok(())), Err("launcher-prefix-read"));
    }

    #[test]
    fn signed_prefix_read_or_deadline_failure_never_produces_a_cleanup_digest() {
        assert_eq!(prefix_hash(launcher::LIMITS[0]+1, |_, _| panic!("source entered"),
            |_, _| panic!("target entered"), || panic!("clock entered")), Err("launcher-prefix-size"));
        for failure in 0..3 {
            let source = b"abcdef";
            let mut ticks = 0;
            let result = prefix_hash(3,
                |at, out| if failure == 0 { Err("source-refused") } else { read_bytes(source, at, out, 1) },
                |at, out| if failure == 1 { Err("target-refused") } else { read_bytes(&source[..3], at, out, 1) },
                || { ticks += 1; if failure == 2 && ticks == 3 { Err("deadline") } else { Ok(()) } });
            assert_eq!(result, Err(["source-refused", "target-refused", "deadline"][failure]));
        }
        assert_eq!(prefix_hash(3, |_, out| Ok(out.len()+1),
            |at, out| read_bytes(b"abc", at, out, 3), || Ok(())), Err("launcher-prefix-read"));
        assert_eq!(prefix_hash(3, |at, out| read_bytes(b"abc", at, out, 3),
            |_, out| Ok(out.len()+1), || Ok(())), Err("launcher-prefix-read"));
    }
}
