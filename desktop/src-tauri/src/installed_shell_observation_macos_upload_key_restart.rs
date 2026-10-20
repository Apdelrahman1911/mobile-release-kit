//! Fixed second-process reuse, on the EXISTING Observation/Relay.
//! The first process has already really quit before the caller may launch this
//! case. Nothing here imports its Trace, preview, material, path or finality.
use super::*;
use crate::asset_session::InstalledUploadColdState;

pub(crate) const SCOPE: &str = "upload-key-cold-restart";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Unlock,
    Context,
    Load,
    Bind,
    Lock,
}
impl Action {
    fn index(self) -> u8 {
        match self {
            Self::Unlock => 0,
            Self::Context => 1,
            Self::Load => 2,
            Self::Bind => 3,
            Self::Lock => 4,
        }
    }
    fn original(self) -> u32 {
        match self {
            Self::Unlock => 2,
            Self::Context | Self::Load => 3,
            Self::Bind => 4,
            Self::Lock => 5,
        }
    }
}

#[derive(Default)]
pub(crate) struct Flow {
    next: AtomicU8,
    pub(crate) native: Mutex<InstalledUploadColdState>,
}
impl Flow {
    pub(crate) fn select(
        &self,
        control: Arc<Control>,
        document: &Arc<()>,
        action: Action,
        original: u32,
    ) -> Option<Selection> {
        if !std::ptr::eq(self, &control.upload.cold)
            || control.case != super::super::Case::UploadKey(Case::ColdReopen)
            || !control.permits(document)
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
        originals == 5 && self.next.load(Ordering::SeqCst) == 5
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
        self.control.case == super::super::Case::UploadKey(Case::ColdReopen)
            && self
                .document
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, document))
            && self.action.original() == original
            && self.control.upload.cold.next.load(Ordering::SeqCst) == self.action.index() + 1
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
    Open,
    Opened,
    Unlock,
    Unlocked,
    Context,
    Load,
    Loaded,
    Bind,
    Bound,
    Lock,
    Locked,
}
#[derive(Default)]
pub(super) struct Record {
    opened: bool,
    unlocked: bool,
    loaded: bool,
    bound: bool,
    lookup: Option<Value>,
}

impl Observation {
    pub(super) fn cold_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        let Some(control) = &self.vault else {
            self.fail_with("upload-key-original-contract");
            return;
        };
        if control.case != super::super::Case::UploadKey(Case::ColdReopen) {
            self.fail_with("upload-key-original-contract");
            return;
        }
        let result: Result<Option<Step>, BridgeError> = (|| {
            let asset = |error: crate::asset_commands::AssetError| {
                if error.reason == crate::asset_commands::Reason::CleanupUnknown {
                    BridgeError::cleanup_unknown()
                } else {
                    BridgeError::invalid()
                }
            };
            Ok(match step {
                Step::Open => {
                    document
                        .installed_macos_vault_action(super::super::Action::Open)
                        .map_err(asset)?;
                    Some(Step::Opened)
                }
                Step::Opened | Step::Unlocked | Step::Locked => {
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
                        Step::Opened
                            if snapshot.originals == 2
                                && snapshot.state == Some("locked")
                                && !snapshot.key_present =>
                        {
                            vault.upload.cold.opened = true;
                            Some(Step::Unlock)
                        }
                        Step::Unlocked
                            if snapshot.originals == 3
                                && snapshot.state == Some("unlocked")
                                && snapshot.key_present =>
                        {
                            let helper = snapshot
                                .lookup
                                .as_ref()
                                .filter(|value| value.successful_consumption())
                                .ok_or_else(BridgeError::invalid)?;
                            vault.upload.cold.lookup = Some(helper.value());
                            vault.upload.cold.unlocked = true;
                            Some(Step::Context)
                        }
                        Step::Locked if snapshot.originals == 5 && snapshot.empty => {
                            if !control.finish(5) || record.fixture.verify(true).is_err() {
                                return Err(BridgeError::invalid());
                            }
                            record
                                .vault_record
                                .as_mut()
                                .ok_or_else(BridgeError::invalid)?
                                .original_count = 5;
                            record.file_readback = true;
                            record.step = super::super::super::Step::Close;
                            return Ok(None);
                        }
                        _ => return Err(BridgeError::invalid()),
                    }
                }
                Step::Unlock => {
                    document.installed_cold_unlock().map_err(asset)?;
                    Some(Step::Unlocked)
                }
                Step::Context => {
                    let project = self
                        .record()
                        .and_then(|record| {
                            record.project.as_ref().map(|project| project.id.clone())
                        })
                        .ok_or_else(BridgeError::invalid)?;
                    document
                        .installed_cold_context(&self.base, &project)
                        .map_err(asset)?;
                    Some(Step::Load)
                }
                Step::Load => {
                    document.installed_cold_load().map_err(asset)?;
                    Some(Step::Loaded)
                }
                Step::Loaded => match document.installed_cold_loaded() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .cold
                            .loaded = true;
                        Some(Step::Bind)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::Bind => {
                    document.installed_cold_bind().map_err(asset)?;
                    Some(Step::Bound)
                }
                Step::Bound => match document.installed_cold_bound() {
                    Some(true) => {
                        self.record()
                            .ok_or_else(BridgeError::invalid)?
                            .vault_record
                            .as_mut()
                            .ok_or_else(BridgeError::invalid)?
                            .upload
                            .cold
                            .bound = true;
                        Some(Step::Lock)
                    }
                    Some(false) => return Err(BridgeError::invalid()),
                    None => None,
                },
                Step::Lock => {
                    document.installed_cold_lock().map_err(asset)?;
                    Some(Step::Locked)
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
                if record.step != super::super::super::Step::UploadKey(super::Step::Cold(step)) {
                    self.fail_with("upload-key-original-contract");
                    return;
                }
                record.step = super::super::super::Step::UploadKey(super::Step::Cold(next));
            }
            Ok(None) => {}
            Err(_) => self.fail_with("upload-key-original-contract"),
        }
    }
}

pub(super) fn report(record: &super::super::Record, control: &Control) -> Option<Value> {
    let cold = &record.upload.cold;
    if control.case != super::super::Case::UploadKey(Case::ColdReopen)
        || !control.completed()
        || !record.final_originals
        || record.original_count != 5
        || !cold.opened
        || !cold.unlocked
        || !cold.loaded
        || !cold.bound
        || cold.lookup.is_none()
    {
        return None;
    }
    Some(
        json!({"mechanism":"fresh-process-upload-key-reuse-v1","normalGenerationEnabled":false,
        "execution":"executed","testResult":"positive","openedExisting":true,
        "initialized":false,"generationAttempted":false,"lookupHelper":cold.lookup,
        "inventoryRows":1,"authenticatedStoredRead":true,"explicitlyBoundSavedKey":true,
        "originalCount":6,"allOriginalsSettled":true,"finalDocumentEmpty":true,
        "automaticallyAssigned":false,"backupCreated":false,"releaseSigningQualified":false,
        "physicalMacEvidence":false,"privateContentsExported":false,
        "rowRetirement":"disposable-hosted-account-only"}),
    )
}

pub(super) fn data_checks() -> bool {
    // Passive comparison tests only. None registers a Control or supplies a
    // native preview, candidate, Keychain return, Store outcome or join.
    let document = Arc::new(());
    let other = Arc::new(());
    let control = Arc::new(Control {
        case: super::super::Case::UploadKey(Case::ColdReopen),
        root: PathBuf::from("/Users/inert/cold"),
        project: PathBuf::from("/private/tmp/inert-cold"),
        original: OnceLock::new(),
        document: OnceLock::new(),
        claimed: AtomicBool::new(false),
        returned: AtomicBool::new(false),
        next: AtomicU8::new(1),
        checkpoint: AtomicBool::new(false),
        complete: AtomicBool::new(false),
        quit: AtomicU8::new(6),
        upload: super::Flow::default(),
    });
    if control
        .upload
        .cold
        .select(control.clone(), &document, Action::Unlock, 2)
        .is_some()
        || control
            .select(&document, super::super::Action::Prepare, 2)
            .is_some()
        || control
            .upload
            .select(control.clone(), &document, super::Action::Create, 4)
            .is_some()
    {
        return false;
    }
    for action in [
        Action::Unlock,
        Action::Context,
        Action::Load,
        Action::Bind,
        Action::Lock,
    ] {
        control
            .upload
            .cold
            .next
            .store(action.index() + 1, Ordering::SeqCst);
        let selection = Selection {
            control: control.clone(),
            document: Arc::downgrade(&document),
            action,
            spent: AtomicBool::new(false),
        };
        if !selection.matches(&document, action.original())
            || selection.matches(&other, action.original())
            || selection.matches(&document, action.original() + 1)
        {
            return false;
        }
        control
            .upload
            .cold
            .next
            .store(action.index(), Ordering::SeqCst);
        if selection.matches(&document, action.original()) {
            return false;
        }
    }
    for next in 0..=6 {
        control.upload.cold.next.store(next, Ordering::SeqCst);
        for originals in 0..=7 {
            if control.upload.cold.finished(originals) != (next == 5 && originals == 5) {
                return false;
            }
        }
    }
    !control.permits(&document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_flow_refuses_unregistered_and_wrong_original_data() {
        assert!(data_checks());
    }

    #[test]
    fn paired_fixture_name_does_not_grant_the_generation_action_sequence() {
        assert_eq!(Case::ColdProduce.fixture_name(), SCOPE);
        assert_eq!(Case::ColdReopen.fixture_name(), SCOPE);
        for case in [Case::RoundTrip, Case::StopBeforeGo, Case::StopAfterNew] {
            assert_eq!(case.fixture_name(), case.name());
            assert_ne!(case.fixture_name(), SCOPE);
        }
        for action in [
            super::super::Action::Context,
            super::super::Action::Prepare,
            super::super::Action::Create,
            super::super::Action::Read,
            super::super::Action::Relock,
        ] {
            assert!(!action.allowed(Case::ColdReopen));
            assert_eq!(
                action.allowed(Case::ColdProduce),
                action.allowed(Case::RoundTrip)
            );
        }
        // A counter comparison cannot supply the native all-originals guard.
        assert!(!Flow::default().finished(5));
    }
}
