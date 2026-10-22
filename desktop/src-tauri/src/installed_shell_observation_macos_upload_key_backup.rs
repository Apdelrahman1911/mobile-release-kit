//! One finite backend-without-pickers continuation of the EXISTING generated
//! upload-key Observation/Relay. No runner, generic phase executor or renderer
//! control. Every action below calls the real Document/vault service original.
use super::*;
use crate::asset_session::InstalledUploadBackupTrace;

pub(crate) const SCOPE: &str = "upload-key-backup-roundtrip";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Export,
    LockSource,
    Open,
    Prepare,
    Initialize,
    Context,
    Import,
    Load,
    Bind,
    LockTarget,
    CancelImport,
}
impl Action {
    fn index(self) -> u8 {
        match self {
            Self::Export => 0,
            Self::LockSource => 1,
            Self::Open => 2,
            Self::Prepare => 3,
            Self::Initialize => 4,
            Self::Context => 5,
            Self::Import => 6,
            Self::Load => 7,
            Self::Bind => 8,
            Self::LockTarget => 9,
            Self::CancelImport => 9,
        }
    }
    fn original(self) -> u32 {
        match self {
            Self::Export => 5,
            Self::LockSource | Self::Open => 6,
            Self::Prepare => 7,
            Self::Initialize => 8,
            Self::Context | Self::Import => 9,
            Self::Load => 10,
            Self::Bind => 11,
            Self::LockTarget | Self::CancelImport => 12,
        }
    }
}
#[derive(Default)]
pub(crate) struct Flow {
    next: AtomicU8,
    pub(crate) native: Mutex<InstalledUploadBackupTrace>,
}
impl Flow {
    pub(crate) fn phase(&self) -> u8 { self.next.load(Ordering::SeqCst) }
    pub(crate) fn select(
        &self,
        control: Arc<Control>,
        document: &Arc<()>,
        action: Action,
        original: u32,
    ) -> Option<Selection> {
        if !std::ptr::eq(self, &control.upload.backup)
            || !matches!(control.case, super::super::Case::UploadKey(Case::BackupRoundTrip | Case::BackupCli))
            || action == Action::CancelImport && control.case != super::super::Case::UploadKey(Case::BackupCli)
            || action == Action::LockTarget && control.case == super::super::Case::UploadKey(Case::BackupCli)
            || !control.permits(document)
            || control.upload.next.load(Ordering::SeqCst) != 8
            || original != action.original()
            || self
                .next
                .compare_exchange(
                    action.index(),
                    action.index() + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_err()
        {
            return None;
        }
        Some(Selection {
            control,
            document: Arc::downgrade(document),
            action,
            spent: AtomicBool::new(false),
        })
    }
    pub(super) fn finished(&self, originals: usize) -> bool {
        originals == 12 && self.next.load(Ordering::SeqCst) == 10
    }
}
pub(crate) struct Selection {
    control: Arc<Control>,
    document: Weak<()>,
    action: Action,
    spent: AtomicBool,
}
impl Selection {
    fn matches(&self, document: &Arc<()>, original: u32) -> bool {
        matches!(self.control.case, super::super::Case::UploadKey(Case::BackupRoundTrip | Case::BackupCli))
            && (self.action != Action::CancelImport || self.control.case == super::super::Case::UploadKey(Case::BackupCli))
            && self
                .document
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, document))
            && original == self.action.original()
            && self.control.upload.next.load(Ordering::SeqCst) == 8
            && self.control.upload.backup.next.load(Ordering::SeqCst) == self.action.index() + 1
    }
    pub(crate) fn consume(self, document: &Arc<()>, original: u32) -> Option<Arc<Control>> {
        (self.control.permits(document)
            && self.matches(document, original)
            && !self.spent.swap(true, Ordering::SeqCst))
        .then_some(self.control)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super::super) enum Step {
    Export,
    Exported,
    LockSource,
    SourceLocked,
    Open,
    Opened,
    Prepare,
    Prepared,
    Initialize,
    Initialized,
    Context,
    Import,
    Imported,
    Load,
    Loaded,
    Bind,
    Bound,
    LockTarget,
    TargetLocked,
}
#[derive(Default)]
pub(super) struct Record {
    exported: bool,
    source_locked: bool,
    opened: bool,
    initialized: bool,
    imported: bool,
    loaded: bool,
    bound: bool,
    initialize: Option<Value>,
    storage: Option<Value>,
}

impl Observation {
    pub(super) fn backup_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        let Some(control) = &self.vault else {
            self.fail_with("upload-key-original-contract");
            return;
        };
        if control.case != super::super::Case::UploadKey(Case::BackupRoundTrip) {
            self.fail_with("upload-key-original-contract");
            return;
        }
        let result: Result<Option<Step>, BridgeError> = (|| {
            let asset = |_: crate::asset_commands::AssetError| BridgeError::invalid();
            Ok(match step {
                Step::Export => {
                    document
                        .installed_generated_backup_export()
                        .map_err(asset)?;
                    Some(Step::Exported)
                }
                Step::Exported => match document.installed_generated_backup_exported() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .backup
                            .exported = true;
                        Some(Step::LockSource)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::LockSource => {
                    document
                        .installed_generated_backup_lock_source()
                        .map_err(asset)?;
                    Some(Step::SourceLocked)
                }
                Step::Open => {
                    document.installed_generated_backup_open().map_err(asset)?;
                    Some(Step::Opened)
                }
                Step::Prepare => {
                    document
                        .installed_generated_backup_prepare()
                        .map_err(asset)?;
                    Some(Step::Prepared)
                }
                Step::Initialize => {
                    document
                        .installed_generated_backup_initialize()
                        .map_err(asset)?;
                    Some(Step::Initialized)
                }
                Step::Context => {
                    let project = self
                        .record()
                        .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
                        .ok_or_else(BridgeError::invalid)?;
                    document
                        .installed_generated_backup_context(&self.base, &project)
                        .map_err(asset)?;
                    Some(Step::Import)
                }
                Step::Import => {
                    document
                        .installed_generated_backup_import()
                        .map_err(asset)?;
                    Some(Step::Imported)
                }
                Step::Imported => match document.installed_generated_backup_imported() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .backup
                            .imported = true;
                        Some(Step::Load)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::Load => {
                    document.installed_generated_backup_load().map_err(asset)?;
                    Some(Step::Loaded)
                }
                Step::Loaded => match document.installed_generated_backup_loaded() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .backup
                            .loaded = true;
                        Some(Step::Bind)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::Bind => {
                    document.installed_generated_backup_bind().map_err(asset)?;
                    Some(Step::Bound)
                }
                Step::Bound => match document.installed_generated_backup_bound() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .backup
                            .bound = true;
                        Some(Step::LockTarget)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::LockTarget => {
                    document
                        .installed_generated_backup_lock_target()
                        .map_err(asset)?;
                    Some(Step::TargetLocked)
                }
                Step::SourceLocked
                | Step::Opened
                | Step::Prepared
                | Step::Initialized
                | Step::TargetLocked => {
                    let Some(snapshot) = document.installed_macos_vault_snapshot() else {
                        return Ok(None);
                    };
                    if snapshot.unknown {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    if !snapshot.originals_settled {
                        return Ok(None);
                    }
                    let mut record = self.record().ok_or_else(BridgeError::invalid)?;
                    let vault = record
                        .vault_record
                        .as_mut()
                        .ok_or_else(BridgeError::invalid)?;
                    match step {
                        Step::SourceLocked if snapshot.originals == 6 && snapshot.empty => {
                            vault.upload.backup.source_locked = true;
                            Some(Step::Open)
                        }
                        Step::Opened
                            if snapshot.originals == 7
                                && snapshot.state == Some("uninitialized")
                                && !snapshot.key_present =>
                        {
                            vault.upload.backup.opened = true;
                            Some(Step::Prepare)
                        }
                        Step::Prepared
                            if snapshot.originals == 8 && snapshot.initialize_preview =>
                        {
                            Some(Step::Initialize)
                        }
                        Step::Initialized
                            if snapshot.originals == 9
                                && snapshot.state == Some("unlocked")
                                && snapshot.key_present =>
                        {
                            let helper = snapshot
                                .initialize
                                .as_ref()
                                .filter(|h| h.successful_consumption())
                                .ok_or_else(BridgeError::invalid)?;
                            let storage = snapshot
                                .storage
                                .filter(|s| s.reservation_durable() && s.header_durable())
                                .ok_or_else(BridgeError::invalid)?;
                            if !snapshot.preview_consumed {
                                return Err(BridgeError::invalid());
                            }
                            vault.upload.backup.initialize = Some(helper.value());
                            vault.upload.backup.storage = Some(storage.value());
                            vault.upload.backup.initialized = true;
                            Some(Step::Context)
                        }
                        Step::TargetLocked if snapshot.originals == 12 && snapshot.empty => {
                            if !control.finish(12) || record.fixture.verify(true).is_err() {
                                return Err(BridgeError::invalid());
                            }
                            record
                                .vault_record
                                .as_mut()
                                .ok_or_else(BridgeError::invalid)?
                                .original_count = 12;
                            record.file_readback = true;
                            record.step = super::super::super::Step::Close;
                            return Ok(None);
                        }
                        _ => return Err(BridgeError::invalid()),
                    }
                }
            })
        })();
        match result {
            Ok(Some(next)) => {
                if !self.timely() {
                    return;
                }
                let Some(mut record) = self.record() else {
                    return;
                };
                if record.step != super::super::super::Step::UploadKey(super::Step::Backup(step)) {
                    self.fail_with("upload-key-original-contract");
                    return;
                }
                record.step = super::super::super::Step::UploadKey(super::Step::Backup(next));
            }
            Ok(None) => {}
            Err(_) => self.fail_with("upload-key-original-contract"),
        }
    }
}

pub(super) fn report(record: &super::super::Record, control: &Control) -> Option<Value> {
    let data = &record.upload;
    let backup = &data.backup;
    if control.case != super::super::Case::UploadKey(Case::BackupRoundTrip)
        || !control.completed()
        || !record.final_originals
        || record.original_count != 12
        || !record.opened
        || !record.preview_consumed
        || !record.initialized
        || record.initialization.is_none()
        || record.storage.is_none()
        || !data.sample.is_some_and(|sample| sample.positive())
        || !data.repeated_refused
        || !backup.exported
        || !backup.source_locked
        || !backup.opened
        || !backup.initialized
        || !backup.imported
        || !backup.loaded
        || !backup.bound
        || backup.initialize.is_none()
        || backup.storage.is_none()
        || record.not_executed
        || data.not_executed
    {
        return None;
    }
    Some(
        json!({"mechanism":"generated-upload-key-backup-v1","normalGenerationEnabled":false,"normalBackupEnabled":false,
        "backendWithoutPickers":true,"execution":"executed","testResult":"positive",
        "initializeHelper":record.initialization,"storage":record.storage,"generated":data.sample,
        "repeatedCreateRefused":true,"backupCreated":true,"backupOriginalsPublishedJoined":true,
        "sourceVaultLocked":true,"restoredVaultOpenedEmpty":true,"restoredInitializeHelper":backup.initialize,
        "restoredStorage":backup.storage,"restoredNewAuthenticated":true,"freshVaultAndRecord":true,
        "authenticatedStoredRead":true,"explicitlyBoundRestoredKey":true,
        "originalCount":13,"allOriginalsSettled":true,"finalDocumentEmpty":true,
        "automaticallyAssigned":false,"releaseSigningQualified":false,"physicalMacEvidence":false,
        "pickerUxVerified":false,"coldRestartVerified":false,"privateContentsExported":false,
        "rowRetirement":"disposable-hosted-account-only"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_backup_continuation_is_fixed_current_original_and_never_a_registration() {
        let document = Arc::new(());
        let other = Arc::new(());
        let control = Arc::new(Control {
            case: super::super::super::Case::UploadKey(Case::BackupRoundTrip),
            root: PathBuf::from("/Users/inert/fixed/dev.mobile-release-kit.desktop"),
            project: PathBuf::from("/private/tmp/inert-backup"),
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            next: AtomicU8::new(3),
            checkpoint: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            quit: AtomicU8::new(13),
            upload: super::super::Flow::default(),
        });
        control.upload.next.store(8, Ordering::SeqCst);
        for action in [
            Action::Export,
            Action::LockSource,
            Action::Open,
            Action::Prepare,
            Action::Initialize,
            Action::Context,
            Action::Import,
            Action::Load,
            Action::Bind,
            Action::LockTarget,
        ] {
            assert!(control
                .upload
                .backup
                .select(control.clone(), &document, action, action.original())
                .is_none());
            control
                .upload
                .backup
                .next
                .store(action.index() + 1, Ordering::SeqCst);
            let selected = Selection {
                control: control.clone(),
                document: Arc::downgrade(&document),
                action,
                spent: AtomicBool::new(false),
            };
            assert!(selected.matches(&document, action.original()));
            assert!(!selected.matches(&other, action.original()));
            assert!(!selected.matches(&document, action.original() + 1));
            assert!(selected.consume(&document, action.original()).is_none());
        }
        assert!(control.upload.backup.finished(12));
        assert!(!control.upload.backup.finished(11));
        control.upload.backup.next.store(9, Ordering::SeqCst);
        assert!(!control.upload.backup.finished(12));
        assert!(!control.completed()); // DATA above cannot finish a Control.
    }
}
