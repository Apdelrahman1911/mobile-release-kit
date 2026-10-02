//! Three finite, nonshipping journeys through the installed app's ORIGINAL
//! document/child/coordinator and unchanged shipping helper. No raw helper,
//! provider override, supplied key, new worker or second cleanup owner.
use std::{path::{Path, PathBuf}, sync::{Arc, OnceLock, Weak, atomic::{AtomicBool, AtomicU8, Ordering}}};
use serde_json::{json, Value};
use crate::{asset_session::{DocumentBinding, InstalledMacVaultSnapshot}, error::BridgeError};
use super::{Case as OuterCase, Observation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { RoundTrip, StopBeforeGo, StopAfterAdd }
impl Case {
    pub(super) const ALL: [Self; 3] = [Self::RoundTrip, Self::StopBeforeGo, Self::StopAfterAdd];
    pub(super) fn name(self) -> &'static str { match self {
        Self::RoundTrip => "vault-helper-roundtrip", Self::StopBeforeGo => "vault-helper-stop-before-go",
        Self::StopAfterAdd => "vault-helper-stop-after-add",
    } }
    pub(super) fn parse(value: &std::ffi::OsStr) -> Option<Self> { Self::ALL.into_iter().find(|c| value == std::ffi::OsStr::new(c.name())) }
    pub(crate) fn maximum_original(self) -> u32 { if self == Self::RoundTrip { 7 } else { 5 } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action { Open, Prepare, Initialize, LockInitialized, Reopen, Unlock, LockUnlocked }
impl Action {
    fn index(self) -> u8 { match self {
        Self::Open => 0, Self::Prepare => 1, Self::Initialize => 2, Self::LockInitialized => 3,
        Self::Reopen => 4, Self::Unlock => 5, Self::LockUnlocked => 6,
    } }
    pub(crate) fn previous_original(self) -> u32 { match self {
        Self::Open => 1, Self::Prepare => 2, Self::Initialize => 3,
        Self::LockInitialized | Self::Reopen => 4, Self::Unlock => 5, Self::LockUnlocked => 6,
    } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Checkpoint { BeforeGo, SuccessfulAddTerminal }

/// The only selector carried into a shared core body is a one-use value minted
/// by this registration's current sequence. Normal renderer calls never get it.
pub(crate) struct Selection {
    control: Arc<Control>, document: Weak<()>, action: Action, serial: u8, spent: AtomicBool,
}
impl Selection {
    pub(crate) fn consume(self, document: &Arc<()>, action: Action, original: u32, path: Option<&Path>) -> bool {
        self.control.permits(document) && self.claim(document, action, original, path)
    }
    fn claim(&self, document: &Arc<()>, action: Action, original: u32, path: Option<&Path>) -> bool {
        self.action == action && self.serial == action.index() + 1
            && original == action.previous_original()
            && self.document.upgrade().is_some_and(|d| Arc::ptr_eq(&d, document))
            && self.control.next.load(Ordering::SeqCst) == self.serial
            && match action { Action::Open | Action::Reopen => path == Some(self.control.root.as_path()), _ => path.is_none() }
            && !self.spent.swap(true, Ordering::SeqCst)
    }
}

pub(crate) struct Registration { control: Arc<Control>, document: Weak<()> }
pub(crate) struct Control {
    pub(crate) case: Case, root: PathBuf, project: PathBuf,
    original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>,
    claimed: AtomicBool, returned: AtomicBool, next: AtomicU8, checkpoint: AtomicBool,
    complete: AtomicBool, quit: AtomicU8,
}
fn fixture_root(home: &Path, source: &str, run: &str, attempt: &str, case: Case) -> Option<PathBuf> {
    let decimal = |v: &str| !v.is_empty() && v.len() <= 20 && !v.starts_with('0') && v.bytes().all(|b| b.is_ascii_digit());
    if !crate::asset_session::installed_macos_selection_path_bounded(home) || home == Path::new("/")
        || source.len() != 40 || !source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !decimal(run) || !decimal(attempt) { return None; }
    Some(home.join("Library/Application Support")
        .join(format!("mrk-macos-aqua-vault-{source}-{run}-{attempt}"))
        .join(case.name()).join("dev.mobile-release-kit.desktop"))
}
impl Control {
    pub(super) fn new(case: Case, project: &Path, uid: u32) -> Result<Arc<Self>, ()> {
        // Same native account source as the shipping helper, never HOME/TMPDIR.
        // Only the reviewed hosted owner creates the exclusive fixture parents.
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).map_err(|_| ())?.ok_or(())?;
        if user.uid.as_raw() != uid || uid == 0 { return Err(()); }
        let root = fixture_root(&user.dir, option_env!("GITHUB_SHA").ok_or(())?,
            option_env!("GITHUB_RUN_ID").ok_or(())?, option_env!("GITHUB_RUN_ATTEMPT").ok_or(())?, case).ok_or(())?;
        Ok(Arc::new(Self { case, root, project: project.to_path_buf(), original: OnceLock::new(), document: OnceLock::new(),
            claimed: AtomicBool::new(false), returned: AtomicBool::new(false), next: AtomicU8::new(0),
            checkpoint: AtomicBool::new(false), complete: AtomicBool::new(false), quit: AtomicU8::new(case.maximum_original() as u8) }))
    }
    fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| q.case == OuterCase::Vault(self.case)
            && q.vault.as_ref().is_some_and(|c| std::ptr::eq(c.as_ref(), self)))
    }
    pub(crate) fn bound(&self, document: &Arc<()>) -> bool {
        self.claimed.load(Ordering::SeqCst) && self.returned.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some_and(|d| Arc::ptr_eq(&d, document))
            && self.observation().is_some()
    }
    pub(crate) fn permits(&self, document: &Arc<()>) -> bool {
        self.bound(document) && !self.complete.load(Ordering::SeqCst) && self.observation().is_some_and(|q| q.timely())
    }
    pub(crate) fn root(&self) -> &Path { &self.root }
    pub(crate) fn project(&self) -> &Path { &self.project }
    pub(crate) fn select(self: &Arc<Self>, document: &Arc<()>, action: Action, original: u32) -> Option<Selection> {
        if !self.permits(document) || original != action.previous_original()
            || self.case != Case::RoundTrip && action.index() > Action::LockInitialized.index()
            || self.next.compare_exchange(action.index(), action.index() + 1, Ordering::SeqCst, Ordering::SeqCst).is_err() { return None; }
        Some(Selection { control: self.clone(), document: Arc::downgrade(document), action,
            serial: action.index() + 1, spent: AtomicBool::new(false) })
    }
    pub(crate) fn wants(&self, checkpoint: Checkpoint) -> bool {
        matches!((self.case, checkpoint), (Case::StopBeforeGo, Checkpoint::BeforeGo)
            | (Case::StopAfterAdd, Checkpoint::SuccessfulAddTerminal))
    }
    pub(crate) fn record_stop(&self, document: &Arc<()>) -> bool {
        self.permits(document) && self.next.load(Ordering::SeqCst) == Action::Initialize.index() + 1
            && !self.checkpoint.swap(true, Ordering::SeqCst)
    }
    pub(crate) fn stopped_at_checkpoint(&self) -> bool { self.checkpoint.load(Ordering::SeqCst) }
    pub(crate) fn quit_id(&self) -> u32 { u32::from(self.quit.load(Ordering::SeqCst)) }
    pub(crate) fn completed(&self) -> bool { self.complete.load(Ordering::SeqCst) }
    fn finish(&self, originals: usize) -> bool {
        let expected = if originals == 6 { 7 } else if originals == 4 { 5 } else { return false; };
        if self.next.load(Ordering::SeqCst) != if originals == 6 { 7 } else { 4 }
            || expected == 7 && self.case != Case::RoundTrip || self.complete.swap(true, Ordering::SeqCst) { return false; }
        self.quit.store(expected, Ordering::SeqCst); true
    }
    fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &DocumentBinding) -> Result<(), BridgeError> {
        if q.case != OuterCase::Vault(self.case) || std::thread::current().id() != q.main || !q.timely() { return Err(BridgeError::invalid()); }
        let identity = document.installed_macos_project_fields_identity();
        if identity.upgrade().is_none() || self.original.set(Arc::downgrade(q)).is_err()
            || self.document.set(identity.clone()).is_err() { return Err(BridgeError::invalid()); }
        document.register_installed_macos_vault(Registration { control: self.clone(), document: identity })?;
        if self.returned.swap(true, Ordering::SeqCst) { return Err(BridgeError::invalid()); }
        Ok(())
    }
}
impl Registration {
    pub(crate) fn consume(self, document: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        let q = self.control.observation().ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !r.attached || r.started || r.loaded || !q.timely()
            || !self.document.upgrade().is_some_and(|d| Arc::ptr_eq(&d, document))
            || self.control.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        drop(r); Ok(self.control)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Open, Opened, Prepare, Prepared, Initialize, Initialized, Lock, Locked, Reopen, Reopened, Unlock, Unlocked, Relock, Relocked }
#[derive(Clone, Copy)]
pub(super) struct FailureSample { pub(super) step: Step, snapshot: InstalledMacVaultSnapshot }
impl FailureSample {
    pub(super) fn value(self) -> Value {
        json!({"source":"first-original-vault-snapshot", "step":format!("Vault({:?})", self.step),
            "observationOnly":true, "snapshot":self.snapshot})
    }
}
fn latch_unknown(first: &AtomicU8, failed: &AtomicBool, detail: &mut Option<FailureSample>, step: Step,
    snapshot: InstalledMacVaultSnapshot) {
    if snapshot.unknown && super::latch_failure(first, failed, "vault-finality-contract") {
        *detail = Some(FailureSample { step, snapshot });
    }
}
#[derive(Default)]
pub(super) struct Record {
    opened: bool, preview_consumed: bool, initialized: bool, locked: bool, reopened: bool, unlocked: bool,
    relocked: bool, not_executed: bool, original_count: usize, final_originals: bool,
    initialization: Option<Value>, lookup: Option<Value>, storage: Option<Value>,
}

impl Observation {
    pub(crate) fn attach_vault(self: &Arc<Self>, document: &DocumentBinding) -> Result<(), BridgeError> {
        match self.vault.as_ref() { Some(control) => control.attach(self, document), None => Ok(()) }
    }
    pub(super) fn quit_id(&self) -> u32 { self.vault.as_ref().map_or_else(|| self.case.quit_id(), |c| c.quit_id()) }
    pub(super) fn vault_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        let Some(control) = &self.vault else { self.fail_with("vault-original-contract"); return; };
        // Calls below run outside Observation::Record. All action admission and
        // start publication remain the existing document's real core path.
        let action = match step {
            Step::Open => Some((Action::Open, Step::Opened)), Step::Prepare => Some((Action::Prepare, Step::Prepared)),
            Step::Initialize => Some((Action::Initialize, Step::Initialized)), Step::Lock => Some((Action::LockInitialized, Step::Locked)),
            Step::Reopen => Some((Action::Reopen, Step::Reopened)), Step::Unlock => Some((Action::Unlock, Step::Unlocked)),
            Step::Relock => Some((Action::LockUnlocked, Step::Relocked)), _ => None,
        };
        if let Some((action, next)) = action {
            if document.installed_macos_vault_action(action).is_err() { self.fail_with("vault-request-contract"); return; }
            let Some(mut r) = self.record() else { return; };
            if r.step != super::Step::Vault(step) { self.fail_with("vault-original-contract"); return; }
            r.step = super::Step::Vault(next); return;
        }
        let Some(snapshot) = document.installed_macos_vault_snapshot() else { return; };
        if snapshot.unknown {
            // Preserve only this original sample, before the successful-join
            // gate. Missing custody remains unknown; this does not reconcile,
            // retry, clean up, or supply an original finality receipt.
            let Ok(mut r) = self.record.lock() else { self.fail_with("vault-finality-contract"); return; };
            if r.step == super::Step::Vault(step) {
                latch_unknown(&self.failure_reason, &self.failed, &mut r.vault_failure, step, snapshot);
            } else { self.fail_with("vault-finality-contract"); }
            return;
        }
        if !snapshot.originals_settled { return; }
        let Some(mut r) = self.record() else { return; };
        if r.step != super::Step::Vault(step) { self.fail_with("vault-original-contract"); return; }
        let Some(record) = r.vault_record.as_mut() else { self.fail_with("vault-original-contract"); return; };
        let next = match step {
            Step::Opened if snapshot.originals == 2 && snapshot.state == Some("uninitialized") && !snapshot.key_present => {
                record.opened = true; Some(Step::Prepare)
            },
            Step::Prepared if snapshot.originals == 3 && snapshot.initialize_preview => Some(Step::Initialize),
            Step::Initialized if snapshot.originals == 4 => {
                let Some(helper) = snapshot.initialize.as_ref() else { self.fail_with("vault-result-contract"); return; };
                let Some(storage) = snapshot.storage else { self.fail_with("vault-result-contract"); return; };
                record.preview_consumed = snapshot.preview_consumed;
                record.initialization = Some(helper.value()); record.storage = Some(storage.value());
                if !record.preview_consumed || !helper.final_settlement() || !storage.reservation_durable() { self.fail_with("vault-result-contract"); return; }
                let stopped = control.stopped_at_checkpoint();
                if control.case == Case::RoundTrip && helper.successful_consumption()
                    && snapshot.state == Some("unlocked") && snapshot.key_present && storage.header_durable() {
                    record.initialized = true;
                } else if control.case != Case::RoundTrip && stopped && helper.stopped_without_application_candidate()
                    && !storage.header_entered() && !snapshot.key_present {
                    if control.case == Case::StopBeforeGo && (helper.go || helper.request_sent || helper.native_candidate_consumed == Some(true))
                        || control.case == Case::StopAfterAdd && (!helper.successful_add_terminal || helper.native_candidate_consumed != Some(true)) {
                        self.fail_with("vault-result-contract"); return;
                    }
                } else if !stopped && helper.provider_negative() && !helper.application_candidate_constructed
                    && !storage.header_entered() && !snapshot.key_present {
                    // Read-only login Keychain/provider admission refused. This
                    // is a genuine negative, NOT a positive shipping-helper pass.
                    record.not_executed = true;
                } else { self.fail_with("vault-result-contract"); return; }
                Some(Step::Lock)
            },
            Step::Locked if snapshot.originals == 4 && snapshot.empty => {
                record.locked = true;
                if control.case == Case::RoundTrip && !record.not_executed { Some(Step::Reopen) }
                else { record.original_count = 4; None }
            },
            Step::Reopened if snapshot.originals == 5 && snapshot.state == Some("locked") && !snapshot.key_present => {
                record.reopened = true; Some(Step::Unlock)
            },
            Step::Unlocked if snapshot.originals == 6 && snapshot.state == Some("unlocked") && snapshot.key_present => {
                let Some(lookup) = snapshot.lookup.as_ref().filter(|s| s.successful_consumption()) else { self.fail_with("vault-result-contract"); return; };
                record.lookup = Some(lookup.value()); record.unlocked = true; Some(Step::Relock)
            },
            Step::Relocked if snapshot.originals == 6 && snapshot.empty => {
                record.relocked = true; record.original_count = 6; None
            },
            _ => { self.fail_with("vault-result-contract"); return; },
        };
        if let Some(next) = next { r.step = super::Step::Vault(next); }
        else {
            if !control.finish(snapshot.originals) || r.fixture.verify(false).is_err() { self.fail_with("vault-finality-contract"); return; }
            r.file_readback = true; r.step = super::Step::Close;
        }
    }
}
impl Record {
    pub(super) fn final_originals(&mut self, snapshot: &InstalledMacVaultSnapshot, control: &Control) -> bool {
        if !control.completed() || snapshot.unknown || !snapshot.empty || !snapshot.originals_settled
            || snapshot.originals != self.original_count + 1 || snapshot.originals != control.quit_id() as usize { return false; }
        self.final_originals = true; true
    }
    pub(super) fn report(&self, control: &Control) -> Option<Value> {
        if !self.final_originals || !self.opened || !self.preview_consumed || !self.locked
            || !control.completed() || self.initialization.is_none() || self.storage.is_none()
            || control.case == Case::RoundTrip && !self.not_executed && !(self.initialized && self.reopened && self.unlocked && self.relocked && self.lookup.is_some()) { return None; }
        // This is the compiled selector, not proof that this selected helper
        // journey exercised the ordinary application/UI route.
        Some(json!({"mechanism":"original-document-shipping-helper-v1",
            "normalPersistenceEnabled":crate::runtime::INSTALLED_MAC_PERSISTENCE_QUALIFIED,
            "execution":if self.not_executed {"not-executed-provider-prerequisite"} else {"executed"},
            "testResult":if self.not_executed {"not-executed"} else if control.case == Case::RoundTrip {"positive"} else {"expected-stop"},
            "checkpoint":match control.case {Case::RoundTrip=>"none",Case::StopBeforeGo=>"before-helper-go",Case::StopAfterAdd=>"successful-add-terminal-before-application-candidate"},
            "checkpointObserved":control.stopped_at_checkpoint(),
            "nativeLookupMayAlreadyHaveConsumed":control.case == Case::StopAfterAdd,
            "openedEmpty":self.opened,"previewConsumedOnce":self.preview_consumed,
            "initialized":self.initialized,"locked":self.locked,"reopened":self.reopened,"unlocked":self.unlocked,"relocked":self.relocked,
            "initializeHelper":self.initialization,"lookupHelper":self.lookup,"storage":self.storage,
            "originalCount":self.original_count + 1,"allOriginalsSettled":self.final_originals,"finalDocumentEmpty":true,
            "syntheticKeychainRowRetirement":"disposable-hosted-account-only","physicalMacEvidence":false}))
    }
}

pub(super) fn data_checks() -> bool {
    // Pure shape/sequence DATA. No user lookup, document, key, file or helper.
    let source = "0123456789abcdef0123456789abcdef01234567";
    for case in Case::ALL {
        if Case::parse(std::ffi::OsStr::new(case.name())) != Some(case)
            || fixture_root(Path::new("/Users/runner"), source, "1", "2", case)
                != Some(PathBuf::from(format!("/Users/runner/Library/Application Support/mrk-macos-aqua-vault-{source}-1-2/{}/dev.mobile-release-kit.desktop",case.name()))) { return false; }
    }
    for bad in ["", "00", "0", "-1", "1/2"] { if fixture_root(Path::new("/Users/runner"), source, bad, "2", Case::RoundTrip).is_some() { return false; } }
    for bad in ["/", "/Users/../runner", "/Users//runner", "Users/runner"] { if fixture_root(Path::new(bad), source, "1", "2", Case::RoundTrip).is_some() { return false; } }
    let root = fixture_root(Path::new("/Users/runner"), source, "1", "2", Case::RoundTrip).unwrap();
    let inert = |case: Case, next: u8| Arc::new(Control { case,root:root.clone(),project:PathBuf::from("/private/tmp/fixed-project"),
        original:OnceLock::new(),document:OnceLock::new(),claimed:AtomicBool::new(false),returned:AtomicBool::new(false),
        next:AtomicU8::new(next),checkpoint:AtomicBool::new(false),complete:AtomicBool::new(false),quit:AtomicU8::new(case.maximum_original() as u8) });
    let document=Arc::new(());let other=Arc::new(());let control=inert(Case::RoundTrip,1);
    let selection=Selection {control:control.clone(),document:Arc::downgrade(&document),action:Action::Open,serial:1,spent:AtomicBool::new(false)};
    if control.permits(&document) // An unregistered/inert owner can never use core methods.
        || selection.claim(&other,Action::Open,1,Some(&root))
        || selection.claim(&document,Action::Prepare,1,Some(&root))
        || selection.claim(&document,Action::Open,2,Some(&root))
        || selection.claim(&document,Action::Open,1,Some(Path::new("/Users/runner/elsewhere"))) { return false; }
    control.next.store(2,Ordering::SeqCst);
    if selection.claim(&document,Action::Open,1,Some(&root)) { return false; }
    control.next.store(1,Ordering::SeqCst);
    if !selection.claim(&document,Action::Open,1,Some(&root)) || selection.claim(&document,Action::Open,1,Some(&root)) { return false; }
    let spent_document=Arc::new(());
    let stale=Selection {control:control.clone(),document:Arc::downgrade(&spent_document),action:Action::Open,serial:1,spent:AtomicBool::new(false)};
    drop(spent_document);
    if stale.claim(&document,Action::Open,1,Some(&root)) { return false; }
    let control=inert(Case::StopAfterAdd,4);
    if control.finish(6) || !control.finish(4) || control.finish(4) || control.quit_id()!=5 { return false; }
    let mut record=Record {original_count:4,..Record::default()};
    let mut snapshot=InstalledMacVaultSnapshot {unknown:false,originals:5,originals_settled:true,empty:true,state:None,
        document_unknown:false,exhausted:false,lost_observed:false,original_bound:true,
        operation_id:None,operation_phase:None,operation_reason:None,operation_settlement:None,
        key_present:false,initialize_preview:false,preview_consumed:true,storage:None,initialize:None,lookup:None,
        initialize_transport:None,lookup_transport:None};
    if !record.final_originals(&snapshot,&control) { return false; }
    snapshot.unknown=true;if record.final_originals(&snapshot,&control) { return false; }snapshot.unknown=false;
    snapshot.originals_settled=false;if record.final_originals(&snapshot,&control) { return false; }snapshot.originals_settled=true;
    snapshot.empty=false;if record.final_originals(&snapshot,&control) { return false; }snapshot.empty=true;
    snapshot.originals=6;if record.final_originals(&snapshot,&control) { return false; }
    let first=AtomicU8::new(0);let failed=AtomicBool::new(false);let mut detail=None;
    latch_unknown(&first,&failed,&mut detail,Step::Initialized,snapshot);
    if detail.is_some() || failed.load(Ordering::SeqCst) { return false; }
    snapshot.unknown=true;snapshot.document_unknown=true;
    latch_unknown(&first,&failed,&mut detail,Step::Initialized,snapshot);
    let Some(sample)=detail else { return false; };
    if sample.step!=Step::Initialized || !sample.snapshot.unknown || !sample.snapshot.document_unknown
        || super::first_failure_reason(&first)!=Some("vault-finality-contract") { return false; }
    snapshot.document_unknown=false;snapshot.lost_observed=true;
    latch_unknown(&first,&failed,&mut detail,Step::Unlocked,snapshot);
    if detail.is_none_or(|s|s.step!=Step::Initialized || !s.snapshot.document_unknown || s.snapshot.lost_observed) { return false; }
    let first=AtomicU8::new(0);let failed=AtomicBool::new(false);let mut absent=None;
    super::latch_failure(&first,&failed,"observer-deadline");
    latch_unknown(&first,&failed,&mut absent,Step::Initialized,snapshot);
    if absent.is_some() || super::first_failure_reason(&first)!=Some("observer-deadline") { return false; }
    let roundtrip=inert(Case::RoundTrip,7);
    roundtrip.finish(6) && roundtrip.quit_id()==7 && crate::vault_keyring_macos::qualification_data_checks()
        && Action::Open.previous_original() == 1 && Action::Initialize.previous_original() == 3
        && Action::Reopen.previous_original() == 4 && Action::LockUnlocked.previous_original() == 6
}
