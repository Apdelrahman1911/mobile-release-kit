//! Three finite upload-key steps in the EXISTING installed Observation/Relay.
//! Initial genuine project picking is unchanged. Everything below that picker
//! calls the same native services directly; no DOM/AX selector or new runner.
use super::*;
use crate::android_toolchain_catalog as catalog;
use crate::asset_session::{InstalledUploadSample, InstalledUploadTrace};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    RoundTrip,
    StopBeforeGo,
    StopAfterNew,
}
impl Case {
    pub(super) const ALL: [Self; 3] = [Self::RoundTrip, Self::StopBeforeGo, Self::StopAfterNew];
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RoundTrip => "upload-key-roundtrip",
            Self::StopBeforeGo => "upload-key-stop-before-go",
            Self::StopAfterNew => "upload-key-stop-after-new",
        }
    }
    pub(super) fn parse(value: &std::ffi::OsStr) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| value == std::ffi::OsStr::new(c.name()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Context,
    Refresh,
    Recover,
    Select,
    Saved,
    Prepare,
    Create,
    RefuseRepeat,
    Lock,
    Reopen,
    Unlock,
    Recontext,
    Read,
    Relock,
    RecoverySaved,
    RecoveryPrepare,
    AcknowledgeUnstarted,
    RecoveredRelock,
    Missing,
}
impl Action {
    fn index(self) -> u8 {
        match self {
            Self::Context => 0,
            Self::Refresh => 1,
            Self::Recover => 2,
            Self::Select => 3,
            Self::Saved => 4,
            Self::Prepare => 5,
            Self::Create => 6,
            Self::RefuseRepeat => 7,
            Self::Lock => 8,
            Self::Reopen => 9,
            Self::Unlock => 10,
            Self::Recontext => 11,
            Self::Read => 12,
            Self::Relock => 13,
            Self::RecoverySaved => 12,
            Self::RecoveryPrepare => 13,
            Self::AcknowledgeUnstarted => 14,
            Self::RecoveredRelock => 15,
            Self::Missing => 254,
        }
    }
    fn original(self) -> u32 {
        match self {
            Self::RefuseRepeat | Self::Lock | Self::Reopen => 5,
            Self::Unlock => 6,
            Self::Recontext | Self::Read | Self::RecoverySaved | Self::RecoveryPrepare | Self::AcknowledgeUnstarted => 7,
            Self::Relock | Self::RecoveredRelock => 8,
            _ => 4,
        }
    }
    fn allowed(self, case: Case) -> bool {
        match self {
            Self::RecoverySaved | Self::RecoveryPrepare | Self::AcknowledgeUnstarted | Self::RecoveredRelock => case == Case::StopBeforeGo,
            Self::Read | Self::Relock => case != Case::StopBeforeGo,
            _ => true,
        }
    }
    pub(crate) fn creates(self) -> bool {
        matches!(self, Self::Create | Self::RefuseRepeat)
    }
}

#[derive(Default)]
pub(crate) struct Flow {
    next: AtomicU8,
    pub(crate) trace: Mutex<InstalledUploadTrace>,
}
impl Flow {
    pub(crate) fn case(&self, case: super::Case) -> Option<Case> {
        if let super::Case::UploadKey(case) = case {
            Some(case)
        } else {
            None
        }
    }
    pub(crate) fn select(
        &self,
        control: Arc<Control>,
        document: &Arc<()>,
        action: Action,
        original: u32,
    ) -> Option<Selection> {
        if !std::ptr::eq(self, &control.upload)
            || !self.case(control.case).is_some_and(|case| action.allowed(case))
            || !control.permits(document)
            || original != action.original()
        {
            return None;
        }
        let (before, after) = if action == Action::Missing {
            (self.next.load(Ordering::SeqCst), 255)
        } else {
            (action.index(), action.index() + 1)
        };
        // No tools may finish safely BEFORE private state preparation,
        // never reinterpret an already-started or uncertain original as absent.
        if action == Action::Missing && !(2..=3).contains(&before) {
            return None;
        }
        if self
            .next
            .compare_exchange(before, after, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None;
        }
        Some(Selection {
            control,
            document: Arc::downgrade(document),
            action,
            serial: after,
            spent: AtomicBool::new(false),
        })
    }
    pub(super) fn finished(&self, originals: usize) -> bool {
        (originals == 8 && matches!(self.next.load(Ordering::SeqCst), 14 | 16))
            || (originals == 4 && self.next.load(Ordering::SeqCst) == 255)
    }
}

/// Native-only, non-Clone and action-bound. Ordinary renderer calls cannot
/// obtain this selector merely because a fixture registration exists.
pub(crate) struct Selection {
    control: Arc<Control>,
    document: Weak<()>,
    action: Action,
    serial: u8,
    spent: AtomicBool,
}
impl Selection {
    pub(crate) fn action(&self) -> Action {
        self.action
    }
    pub(crate) fn consume(
        self,
        document: &Arc<()>,
        original: u32,
        path: Option<&Path>,
    ) -> Option<Arc<Control>> {
        if !self.control.permits(document) || !self.claim(document, original, path) {
            return None;
        }
        Some(self.control)
    }
    fn claim(&self, document: &Arc<()>, original: u32, path: Option<&Path>) -> bool {
        self.control.upload.case(self.control.case).is_some_and(|case| self.action.allowed(case))
            && self.serial
            == if self.action == Action::Missing {
                255
            } else {
                self.action.index() + 1
            }
            && self
                .document
                .upgrade()
                .is_some_and(|same| Arc::ptr_eq(&same, document))
            && original == self.action.original()
            && self.control.upload.next.load(Ordering::SeqCst) == self.serial
            && if matches!(self.action, Action::Prepare | Action::RecoveryPrepare | Action::Reopen) {
                path == Some(self.control.root())
            } else {
                path.is_none()
            }
            && !self.spent.swap(true, Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Step {
    Context,
    Refresh,
    Refreshed,
    Recovered,
    Saved,
    Prepare,
    Create,
    Running,
    Repeat,
    Lock,
    Locked,
    Reopen,
    Reopened,
    Unlock,
    Unlocked,
    Recontext,
    Read,
    Readback,
    RecoverySaved,
    RecoveryPrepare,
    AcknowledgeUnstarted,
    RecoveryReadback,
    Relock,
    Relocked,
    Missing,
    MissingLocked,
}
#[derive(Default)]
pub(super) struct Record {
    pub(super) sample: Option<InstalledUploadSample>,
    repeated_refused: bool,
    readback: bool,
    acknowledged: bool,
    not_executed: bool,
}
#[derive(Clone, Copy)]
pub(in super::super) struct FailureSample {
    sample: InstalledUploadSample,
    repeated_create_refused: bool,
}
impl FailureSample {
    pub(in super::super) fn value(self) -> Value {
        json!({"source":"original-upload-key-sample","observationOnly":true,
    "repeatedCreateRefused":self.repeated_create_refused,
    "exitOrDisposalPermission":false,"sample":self.sample})
    }
}

fn recover(status: &catalog::Status) -> Option<catalog::Recover> {
    if status.phase != catalog::Phase::Ready || status.entries.len() != 1 {
        return None;
    }
    let row = &status.entries[0];
    let cmp = row.recovery.as_ref()?;
    (row.status == catalog::RowStatus::RecoveryRequired
        && cmp.catalog_generation == status.catalog_generation)
        .then(|| catalog::Recover {
            schema_version: 1,
            catalog_generation: cmp.catalog_generation,
            instance: cmp.instance.clone(),
            record_sha256: cmp.record_sha256.clone(),
            inventory_sha256: cmp.inventory_sha256.clone(),
            os_provider_sha256: cmp.os_provider_sha256.clone(),
        })
}
fn select(status: &catalog::Status) -> Option<catalog::Select> {
    if status.phase != catalog::Phase::Ready || status.entries.len() != 1 {
        return None;
    }
    let row = &status.entries[0];
    let cmp = row.selection.as_ref()?;
    (row.status == catalog::RowStatus::VerifiedThisSession
        && cmp.catalog_generation == status.catalog_generation)
        .then(|| catalog::Select {
            schema_version: 1,
            catalog_generation: cmp.catalog_generation,
            instance: cmp.instance.clone(),
            record_sha256: cmp.record_sha256.clone(),
            inventory_sha256: cmp.inventory_sha256.clone(),
            os_provider_sha256: cmp.os_provider_sha256.clone(),
        })
}

impl Observation {
    /// Called by the SAME existing Relay task. An async native startup/saved
    /// observation is awaited by that original; there is no new unjoined task.
    pub(crate) async fn tick_original(self: &Arc<Self>, app: &tauri::AppHandle) {
        let step = self.record().and_then(|r| match r.step {
            super::super::Step::UploadKey(step) => Some(step),
            _ => None,
        });
        if let Some(step) = step {
            if !self.timely() {
                self.tick(app);
                return;
            }
            use tauri::Manager;
            let Some(state) = app.try_state::<crate::shell::ShellState>() else {
                self.fail_with("upload-key-original-contract");
                return;
            };
            self.upload_tick(&state.document, step).await;
        } else {
            self.tick(app);
        }
    }
    async fn upload_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        let Some(control) = &self.vault else {
            self.fail_with("upload-key-original-contract");
            return;
        };
        let Some(case) = control.upload.case(control.case) else {
            self.fail_with("upload-key-original-contract");
            return;
        };
        let result: Result<Option<Step>, BridgeError> = async {
            let asset = |e: crate::asset_commands::AssetError| {
                let _ = e;
                BridgeError::invalid()
            };
            let consume = |action| {
                document
                    .installed_upload_select(action)
                    .and_then(|selection| document.installed_upload_consume(selection, None))
                    .map_err(asset)
            };
            Ok(match step {
                Step::Context => {
                    let project = self
                        .record()
                        .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
                        .ok_or_else(BridgeError::invalid)?;
                    document
                        .installed_upload_context(&self.base, &project, false)
                        .map_err(asset)?;
                    Some(Step::Refresh)
                }
                Step::Refresh => {
                    consume(Action::Refresh)?;
                    document.refresh_android_toolchain_catalog()?;
                    Some(Step::Refreshed)
                }
                Step::Refreshed => {
                    let status = document.android_toolchain_catalog_status()?;
                    if matches!(
                        status.phase,
                        catalog::Phase::Reading | catalog::Phase::Stopping
                    ) {
                        None
                    } else if let Some(input) = recover(&status) {
                        consume(Action::Recover)?;
                        document.recover_android_toolchain(input)?;
                        Some(Step::Recovered)
                    } else if status.phase == catalog::Phase::Ready && status.entries.is_empty() {
                        Some(Step::Missing)
                    } else {
                        return Err(BridgeError::invalid());
                    }
                }
                Step::Recovered => {
                    let status = document.android_toolchain_catalog_status()?;
                    if matches!(
                        status.phase,
                        catalog::Phase::Reading | catalog::Phase::Stopping
                    ) {
                        None
                    } else if let Some(input) = select(&status) {
                        consume(Action::Select)?;
                        let selected = document.select_android_toolchain(input)?;
                        if selected.selected.is_none() {
                            return Err(BridgeError::invalid());
                        }
                        Some(Step::Saved)
                    } else {
                        return Err(BridgeError::invalid());
                    }
                }
                Step::Saved => {
                    document.installed_upload_saved().await.map_err(asset)?;
                    Some(Step::Prepare)
                }
                Step::Prepare => {
                    document.installed_upload_prepare().await.map_err(asset)?;
                    Some(Step::Create)
                }
                Step::Create => {
                    if !document.installed_upload_create(false).map_err(asset)? {
                        return Err(BridgeError::invalid());
                    }
                    Some(Step::Running)
                }
                Step::Running => {
                    let Some(sample) = document.installed_upload_sample() else {
                        return Ok(None);
                    };
                    if sample.positive() {
                        let mut r = self.record().ok_or_else(BridgeError::invalid)?;
                        r.vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .sample = Some(sample);
                        Some(Step::Repeat)
                    } else if sample.cancelled(case) {
                        // Observe only the original positive cleanup/CAS/use
                        // retirement. UserCancelled stays UserCancelled; no
                        // transient retained STOP becomes a pass or an exit.
                        self.record().ok_or_else(BridgeError::invalid)?
                            .vault_record.as_mut().ok_or_else(BridgeError::invalid)?
                            .upload.sample = Some(sample);
                        Some(Step::Repeat)
                    } else {
                        None
                    }
                }
                Step::Repeat => {
                    if !document.installed_upload_create(true).map_err(asset)? {
                        return Err(BridgeError::invalid());
                    }
                    self.record()
                        .ok_or_else(BridgeError::invalid)?
                        .vault_record
                        .as_mut()
                        .ok_or_else(BridgeError::invalid)?
                        .upload
                        .repeated_refused = true;
                    Some(Step::Lock)
                }
                Step::Lock => {
                    document
                        .installed_upload_vault(Action::Lock)
                        .map_err(asset)?;
                    Some(Step::Locked)
                }
                Step::Locked => {
                    let s = document
                        .installed_macos_vault_snapshot()
                        .ok_or_else(BridgeError::invalid)?;
                    if s.unknown {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    if s.empty && s.originals_settled {
                        Some(Step::Reopen)
                    } else {
                        None
                    }
                }
                Step::Reopen => {
                    document
                        .installed_upload_vault(Action::Reopen)
                        .map_err(asset)?;
                    Some(Step::Reopened)
                }
                Step::Reopened => {
                    let s = document
                        .installed_macos_vault_snapshot()
                        .ok_or_else(BridgeError::invalid)?;
                    if s.unknown {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    if s.originals_settled && s.state == Some("locked") && !s.key_present {
                        Some(Step::Unlock)
                    } else {
                        None
                    }
                }
                Step::Unlock => {
                    document
                        .installed_upload_vault(Action::Unlock)
                        .map_err(asset)?;
                    Some(Step::Unlocked)
                }
                Step::Unlocked => {
                    let s = document
                        .installed_macos_vault_snapshot()
                        .ok_or_else(BridgeError::invalid)?;
                    if s.unknown {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    if s.originals_settled
                        && s.state == Some("unlocked")
                        && s.key_present
                        && s.lookup
                            .is_some_and(|lookup| lookup.successful_consumption())
                    {
                        Some(Step::Recontext)
                    } else {
                        None
                    }
                }
                Step::Recontext => {
                    let project = self
                        .record()
                        .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
                        .ok_or_else(BridgeError::invalid)?;
                    document
                        .installed_upload_context(&self.base, &project, true)
                        .map_err(asset)?;
                    Some(if case == Case::StopBeforeGo { Step::RecoverySaved } else { Step::Read })
                }
                Step::Read => {
                    document
                        .installed_upload_vault(Action::Read)
                        .map_err(asset)?;
                    Some(Step::Readback)
                }
                Step::Readback => match document.installed_upload_readback() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .readback = true;
                        Some(Step::Relock)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::RecoverySaved => {
                    document.installed_upload_recovery_saved().await.map_err(asset)?;
                    Some(Step::RecoveryPrepare)
                }
                Step::RecoveryPrepare => {
                    document.installed_upload_recovery_prepare().await.map_err(asset)?;
                    Some(Step::AcknowledgeUnstarted)
                }
                Step::AcknowledgeUnstarted => {
                    document.installed_upload_acknowledge_unstarted().map_err(asset)?;
                    Some(Step::RecoveryReadback)
                }
                Step::RecoveryReadback => match document.installed_upload_acknowledged() {
                    Some(true) => {
                        self.record().ok_or_else(BridgeError::invalid)?
                            .vault_record.as_mut().ok_or_else(BridgeError::invalid)?
                            .upload.acknowledged = true;
                        Some(Step::Relock)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::Relock => {
                    document
                        .installed_upload_vault(if case == Case::StopBeforeGo { Action::RecoveredRelock } else { Action::Relock })
                        .map_err(asset)?;
                    Some(Step::Relocked)
                }
                Step::Missing => {
                    document
                        .installed_upload_vault(Action::Missing)
                        .map_err(asset)?;
                    self.record()
                        .ok_or_else(BridgeError::invalid)?
                        .vault_record
                        .as_mut()
                        .ok_or_else(BridgeError::invalid)?
                        .upload
                        .not_executed = true;
                    Some(Step::MissingLocked)
                }
                Step::Relocked | Step::MissingLocked => {
                    let s = document
                        .installed_macos_vault_snapshot()
                        .ok_or_else(BridgeError::invalid)?;
                    if s.unknown {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    if !s.empty || !s.originals_settled {
                        return Ok(None);
                    }
                    let mut r = self.record().ok_or_else(BridgeError::invalid)?;
                    if !control.finish(s.originals) || r.fixture.verify(true).is_err() {
                        return Err(BridgeError::invalid());
                    }
                    let record = r.vault_record.as_mut().ok_or_else(BridgeError::invalid)?;
                    record.original_count = s.originals;
                    record.locked = true;
                    r.file_readback = true;
                    r.step = super::super::Step::Close;
                    return Ok(None);
                }
            })
        }
        .await;
        match result {
            Ok(Some(next)) => {
                if !self.timely() {
                    return;
                }
                let Some(mut r) = self.record() else {
                    return;
                };
                if r.step != super::super::Step::UploadKey(step) {
                    self.fail_with("upload-key-original-contract");
                    return;
                }
                r.step = super::super::Step::UploadKey(next);
            }
            Ok(None) => {}
            Err(_) => self.fail_with("upload-key-original-contract"),
        }
    }
}

pub(super) fn report(record: &super::Record, control: &Control) -> Option<Value> {
    let case = control.upload.case(control.case)?;
    let data = &record.upload;
    let not_executed = record.not_executed || data.not_executed;
    if !record.final_originals
        || !control.completed()
        || !record.opened
        || !record.preview_consumed
        || !record.locked
        || (!not_executed
            && (!data.sample.is_some_and(|sample| if case == Case::RoundTrip { sample.positive() } else { sample.cancelled(case) })
                || !data.repeated_refused
                || data.readback != (case != Case::StopBeforeGo)
                || data.acknowledged != (case == Case::StopBeforeGo)
                || record.original_count != 8))
    {
        return None;
    }
    Some(
        json!({"mechanism":"same-original-upload-key-v1","normalGenerationEnabled":false,
        "execution":if not_executed{"not-executed-prerequisite"}else{"executed"},
        "testResult":if not_executed{"not-executed"}else if case == Case::RoundTrip{"positive"}else{"cancelled-cleanup"},
        "initializeHelper":record.initialization,"storage":record.storage,
        "generated":data.sample,"repeatedCreateRefused":data.repeated_refused,"authenticatedReopenReadback":data.readback,"stoppedIntentAcknowledged":data.acknowledged,
        "originalCount":record.original_count+1,"allOriginalsSettled":true,"finalDocumentEmpty":true,
        "automaticallyAssigned":false,"backupCreated":false,"releaseSigningQualified":false,
        "physicalMacEvidence":false,"privateContentsExported":false,"rowRetirement":"disposable-hosted-account-only"}),
    )
}

pub(super) fn data_checks() -> bool {
    // Pure selector DATA, not a registered Control or native availability.
    // No User lookup, directory, private scalar or process is constructed.
    let root = PathBuf::from("/Users/inert/upload-key-native-test");
    let inert = || {
        Arc::new(Control {
            case: super::Case::UploadKey(Case::RoundTrip),
            root: root.clone(),
            project: PathBuf::from("/private/tmp/inert-project"),
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            next: AtomicU8::new(3),
            checkpoint: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            quit: AtomicU8::new(9),
            upload: Flow::default(),
        })
    };
    let control = inert();
    let document = Arc::new(());
    let other = Arc::new(());
    let select = |document: &Arc<()>, action: Action| Selection {
        control: control.clone(),
        document: Arc::downgrade(document),
        action,
        serial: action.index() + 1,
        spent: AtomicBool::new(false),
    };
    control.upload.next.store(6, Ordering::SeqCst);
    let selection = select(&document, Action::Prepare);
    if control.permits(&document)
        || control
            .upload
            .select(control.clone(), &document, Action::Create, 4)
            .is_some()
        || Flow::default()
            .select(control.clone(), &document, Action::Prepare, 4)
            .is_some()
        || selection.claim(&other, 4, Some(&root))
        || selection.claim(&document, 5, Some(&root))
        || selection.claim(&document, 4, Some(Path::new("/Users/inert/elsewhere")))
        || selection.claim(&document, 4, None)
    {
        return false;
    }
    control.upload.next.store(7, Ordering::SeqCst);
    if selection.claim(&document, 4, Some(&root)) {
        return false;
    }
    control.upload.next.store(6, Ordering::SeqCst);
    if !selection.claim(&document, 4, Some(&root)) || selection.claim(&document, 4, Some(&root)) {
        return false;
    }
    // Even a matching comparison cannot consume an unregistered original.
    if select(&document, Action::Prepare)
        .consume(&document, 4, Some(&root))
        .is_some()
    {
        return false;
    }
    let dead = Arc::new(());
    let lost = select(&dead, Action::Prepare);
    drop(dead);
    if lost.claim(&document, 4, Some(&root)) || control.upload.finished(5) {
        return false;
    }
    control.upload.next.store(14, Ordering::SeqCst);
    if !control.upload.finished(8) || control.upload.finished(7) || control.upload.finished(9) {
        return false;
    }
    control.upload.next.store(255, Ordering::SeqCst);
    if !control.upload.finished(4) || control.upload.finished(5) {
        return false;
    }
    if Action::AcknowledgeUnstarted.allowed(Case::RoundTrip)
        || Action::RecoveryPrepare.allowed(Case::StopAfterNew)
        || Action::Read.allowed(Case::StopBeforeGo)
        || Action::Relock.allowed(Case::StopBeforeGo)
        || !Action::AcknowledgeUnstarted.allowed(Case::StopBeforeGo)
        || Action::AcknowledgeUnstarted.original() != 7
        || Action::RecoveredRelock.original() != 8
    { return false; }
    control.upload.next.store(16, Ordering::SeqCst);
    if !control.upload.finished(8) || control.upload.finished(9) { return false; }
    Action::Create.original() == 4
        && Action::RefuseRepeat.original() == 5
        && Action::Read.original() == 7
        && Action::Relock.original() == 8
        && Case::ALL
            .iter()
            .all(|case| Case::parse(std::ffi::OsStr::new(case.name())) == Some(*case))
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_actions_keep_original_document_path_and_one_use() {
        assert!(super::data_checks());
    }
}
