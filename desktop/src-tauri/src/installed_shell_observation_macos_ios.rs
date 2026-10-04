//! Finite iOS observations inside the original installed Mac relay.
//! This module owns only comparison DATA and one final-observer hold. The real
//! document, saved-command owner, native books and invocation keep all effects.
use std::{ffi::OsStr, sync::{Arc, Mutex, OnceLock, Weak, atomic::{AtomicBool, AtomicU8, Ordering}}, time::Instant};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use crate::{asset_session::DocumentBinding, error::BridgeError, ios_archive_owner::IOSArchiveOwner,
    ios_archive_protocol as wire};
use super::{Case as ShellCase, Observation};
#[path = "installed_shell_observation_macos_ios_pending.rs"]
mod pending;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { ToolchainPrerequisite, VersionStale, UnsignedArchive, Cancel, Finality,
    SigningInputs, SignedRefusal, SignedCancel, RecoveryEmpty, RecoveryPending, AndroidInputs }
impl Case {
    pub(super) const ALL: [Self; 11] = [Self::ToolchainPrerequisite, Self::VersionStale,
        Self::UnsignedArchive, Self::Cancel, Self::Finality, Self::SigningInputs, Self::SignedRefusal,
        Self::SignedCancel, Self::RecoveryEmpty, Self::RecoveryPending, Self::AndroidInputs];
    pub(super) fn name(self) -> &'static str { match self {
        Self::ToolchainPrerequisite => "ios-toolchain-prerequisite", Self::VersionStale => "ios-version-stale",
        Self::UnsignedArchive => "ios-unsigned-archive", Self::Cancel => "ios-cancel", Self::Finality => "ios-finality",
        Self::SigningInputs => "ios-signing-inputs", Self::SignedRefusal => "ios-signed-refusal",
        Self::SignedCancel => "ios-signed-cancel", Self::RecoveryEmpty => "ios-recovery-empty",
        Self::RecoveryPending => "ios-recovery-pending", Self::AndroidInputs => "android-inputs",
    } }
    pub(super) fn parse(value: &OsStr) -> Option<Self> { Self::ALL.into_iter().find(|case| value == OsStr::new(case.name())) }
    pub(crate) fn session_final_original(self) -> Option<u32> { match self {
        Self::AndroidInputs => Some(18),
        Self::SigningInputs | Self::SignedRefusal | Self::SignedCancel => Some(12),
        _ => None,
    } }
    pub(super) fn input_only(self) -> bool { matches!(self, Self::SigningInputs | Self::AndroidInputs) }
    pub(super) fn inputs(self) -> bool { self.input_only() || self.signed() }
    pub(super) fn signed(self) -> bool { matches!(self, Self::SignedRefusal | Self::SignedCancel) }
    pub(super) fn operation(self) -> Option<wire::Operation> { match self {
        Self::SigningInputs | Self::AndroidInputs => None, Self::SignedRefusal | Self::SignedCancel => Some(wire::Operation::IOSSignedExport),
        Self::RecoveryEmpty | Self::RecoveryPending => Some(wire::Operation::IOSLocalRecovery), _ => Some(wire::Operation::IOSUnsignedArchive),
    } }
    pub(super) fn recovery(self) -> bool { matches!(self, Self::RecoveryEmpty | Self::RecoveryPending) }
    pub(super) fn holds_finality(self) -> bool { matches!(self, Self::Finality | Self::SignedRefusal) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command { Prepare, Start, Status, Cancel }

/// One actual owner snapshot. No public/caller JSON can construct a witness.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OriginalFacts {
    pub(crate) operation_id: String, pub(crate) owner_generation: String,
    pub(crate) inspection_joined: bool, pub(crate) acquisition_joined: bool, pub(crate) attempted: bool,
    pub(crate) child_waited_success: bool, pub(crate) stdin_closed: bool, pub(crate) stdout_eof_closed: bool,
    pub(crate) stderr_eof_closed: bool, pub(crate) io_joined: bool, pub(crate) core_lifetime_settled: bool,
    pub(crate) runtime_ledger_settled: bool, pub(crate) tools_ledger_settled: bool,
    pub(crate) native_settlement_joined: bool, pub(crate) native_integrity: bool,
    pub(crate) driver_joined: bool, pub(crate) manager_joined: bool, pub(crate) observer_joined: bool,
    pub(crate) watchdog_joined: bool, pub(crate) retired_before_cutoff: bool, pub(crate) active_retained: bool,
    pub(crate) resource_unknown: bool, pub(crate) work_ms: u64, pub(crate) hard_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) material_loan_retired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) material_loan_present: Option<bool>,
}
impl OriginalFacts {
    fn settled_body(&self) -> bool {
        crate::edit_protocol::token(&self.operation_id) && crate::edit_protocol::token(&self.owner_generation)
            && self.inspection_joined && self.acquisition_joined && self.attempted && self.child_waited_success
            && self.stdin_closed && self.stdout_eof_closed && self.stderr_eof_closed && self.io_joined
            && self.core_lifetime_settled && self.runtime_ledger_settled && self.tools_ledger_settled
            && self.native_settlement_joined && self.native_integrity && self.driver_joined && self.manager_joined
            && !self.resource_unknown
    }
    fn clocks_for(&self, case: Case) -> bool {
        if case.signed() || case.recovery() {
            (self.work_ms, self.hard_ms, self.cleanup_ms) == (120_000, 250_000, Some(240_000))
        } else { !case.input_only() && (self.work_ms, self.hard_ms, self.cleanup_ms) == (300_000, 310_000, None)
            && self.material_loan_present.is_none() && self.material_loan_retired.is_none() }
    }
    fn held(&self, case: Case) -> bool { self.settled_body() && self.clocks_for(case) && case.holds_finality()
        && !self.observer_joined && !self.watchdog_joined && !self.retired_before_cutoff && self.active_retained
        && (!case.signed() || self.material_loan_present == Some(true) && self.material_loan_retired == Some(false)) }
    fn final_for(&self, case: Case) -> bool { self.settled_body() && self.clocks_for(case) && self.observer_joined && self.watchdog_joined
        && self.retired_before_cutoff && !self.active_retained
        && (!(case.signed() || case.recovery()) || self.material_loan_present == Some(false) && self.material_loan_retired == Some(true)) }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Snapshot { pub(crate) facts: OriginalFacts, pub(crate) terminal: wire::Terminal }

// Private, non-cloneable token. Exact original identities are consumed before
// navigation/IPC, not inferred from a path, label, owner clone or environment.
pub(crate) struct Admission { control: Arc<Control>, document: Weak<()>, owner: Weak<()> }
/// A separate, noncloneable observation registration on the original document.
/// Neither this token nor the archive observer can enable private inputs.
pub(crate) struct SessionRegistration { control: Arc<Control>, document: Weak<()> }
impl SessionRegistration {
    fn claim_original(&self, original: &Arc<()>) -> bool {
        self.document.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
            && self.control.session_registered.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
    pub(crate) fn consume(self, original: &Arc<()>) -> Result<Case, BridgeError> {
        let q = self.control.original.get().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !self.control.case.inputs() || !self.control.permits() || !r.attached || r.started || r.loaded
            || !self.claim_original(original) {
            return Err(BridgeError::invalid());
        }
        // Return this consumed token's own validated Case, never a caller-
        // supplied count/case. The document independently checks availability.
        Ok(self.control.case)
    }
}
impl Admission {
    pub(crate) fn document_matches(&self, original: &Arc<()>) -> bool {
        self.document.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
    }
    pub(crate) fn consume(self, original: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        let q = self.control.original.get().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if self.control.normal_selection_observed.get().is_none()
            || self.document.upgrade().is_none() || !self.owner.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
            || !r.attached || r.started || r.loaded || !q.timely()
            || q.case != ShellCase::Ios(self.control.case)
            || !q.ios.as_ref().is_some_and(|control| Arc::ptr_eq(control, &self.control))
            || self.control.admitted.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        drop(r); Ok(self.control)
    }
}
struct Hold {
    snapshot: Option<Snapshot>, entered: bool, released: bool,
    sender: Option<oneshot::Sender<()>>, receiver: Option<oneshot::Receiver<()>>,
}
pub(crate) struct Control {
    pub(crate) case: Case, original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>, owner: OnceLock<Weak<()>>,
    normal_selection_observed: OnceLock<()>, normal_session_registration_returned: OnceLock<()>,
    admitted: AtomicBool, session_registered: AtomicBool, claimed: AtomicU8, failed: AtomicBool, hold: Mutex<Hold>,
    signed_boundary: Mutex<Option<(String, String, Instant)>>,
}
// Observation history only. A successful DATA transition grants no operation;
// claim_slot still requires the same live document/owner/observation admission.
fn claim_observation_slot(case: Case, claimed: &AtomicU8, index: usize) -> bool {
    let (before, after) = match index {
        0 if case.operation().is_some() => (0, 1),
        1 if case == Case::RecoveryPending => (1, 3),
        _ => return false,
    };
    claimed.compare_exchange(before, after, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}
impl Control {
    pub(super) fn new(case: Case) -> Arc<Self> {
        // Created before any owner work; the channel carries no native custody.
        let (sender, receiver) = oneshot::channel();
        Arc::new(Self { case, original: OnceLock::new(), document: OnceLock::new(), owner: OnceLock::new(),
            normal_selection_observed: OnceLock::new(), normal_session_registration_returned: OnceLock::new(),
            admitted: AtomicBool::new(false), session_registered: AtomicBool::new(false), claimed: AtomicU8::new(0), failed: AtomicBool::new(false),
            signed_boundary: Mutex::new(None),
            hold: Mutex::new(Hold { snapshot: None, entered: false, released: false, sender: Some(sender), receiver: Some(receiver) }) })
    }
    pub(super) fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &DocumentBinding, owner: &IOSArchiveOwner)
        -> Result<(), BridgeError> {
        if q.case != ShellCase::Ios(self.case) || !q.timely() || std::thread::current().id() != q.main {
            return Err(BridgeError::invalid());
        }
        let (doc, bound_owner) = document.installed_ios_identities();
        let direct = owner.installed_ios_identity();
        if doc.upgrade().is_none() || !Weak::ptr_eq(&bound_owner, &direct) || direct.upgrade().is_none() {
            return Err(BridgeError::invalid());
        }
        // Inspect the SAME originals while both observer slots are still empty.
        // The retained marker records returned ordinary availability, not a grant.
        document.observe_installed_macos_normal_selection()?;
        if self.normal_selection_observed.set(()).is_err()
            || self.original.set(Arc::downgrade(q)).is_err() || self.document.set(doc.clone()).is_err()
            || self.owner.set(bound_owner.clone()).is_err() { return Err(BridgeError::invalid()); }
        document.admit_installed_ios(Admission { control: self.clone(), document: doc.clone(), owner: bound_owner })?;
        if self.case.inputs() {
            document.register_installed_macos_session(SessionRegistration { control: self.clone(), document: doc })?;
            // The claim above is not success until the original document has
            // installed its Book and returned. Preserve that historical fact
            // after shutdown, without keeping its original owners alive.
            if self.normal_session_registration_returned.set(()).is_err() { return Err(BridgeError::invalid()); }
        }
        Ok(())
    }
    pub(super) fn normal_session_registered(&self) -> bool {
        self.normal_selection_observed.get().is_some() && self.session_registered.load(Ordering::SeqCst)
            && self.normal_session_registration_returned.get().is_some()
    }
    pub(crate) fn permits(&self) -> bool {
        // Called while the actual owner registry may be held. Never acquire the
        // observation Record or a native/document lock on this eligibility path.
        self.admitted.load(Ordering::SeqCst) && self.normal_selection_observed.get().is_some() && !self.failed.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some() && self.owner.get().and_then(Weak::upgrade).is_some()
            && self.original.get().and_then(Weak::upgrade).is_some_and(|q| q.timely()
                && q.case == ShellCase::Ios(self.case)
                && q.ios.as_ref().is_some_and(|control| std::ptr::eq(control.as_ref(), self)))
    }
    pub(crate) fn claim(&self) -> Result<(), BridgeError> { self.claim_slot(0) }
    pub(crate) fn slot_for(&self, context: &wire::Context) -> Option<usize> {
        if self.case.operation() != Some(context.operation) { return None; }
        if self.case == Case::RecoveryPending {
            return match context.recovery.as_ref()? {
                wire::RecoveryIntent { action: wire::RecoveryAction::Inspect, session: None } => Some(0),
                wire::RecoveryIntent { action: wire::RecoveryAction::Account, session: Some(token) }
                    if crate::edit_protocol::token(token) => Some(1),
                _ => None,
            };
        }
        if self.case == Case::RecoveryEmpty && context.recovery != Some(wire::RecoveryIntent {
            action: wire::RecoveryAction::Inspect, session: None }) { return None; }
        Some(0)
    }
    pub(crate) fn claim_slot(&self, index: usize) -> Result<(), BridgeError> {
        if !self.permits() || !claim_observation_slot(self.case, &self.claimed, index) {
            return Err(BridgeError::invalid());
        }
        Ok(())
    }
    pub(crate) fn slot_claimed(&self, index: usize) -> bool {
        match index { 0 => self.claimed.load(Ordering::SeqCst) == 1,
            1 => self.case == Case::RecoveryPending && self.claimed.load(Ordering::SeqCst) == 3, _ => false }
    }
    pub(crate) fn permits_mode(&self, operation: wire::Operation) -> bool {
        self.case.operation() == Some(operation) && self.permits()
    }
    pub(crate) fn holds_finality(&self) -> bool { self.case.holds_finality() }
    pub(crate) fn signed_cancel_boundary(&self, operation: &str, generation: &str) {
        let Ok(mut original) = self.signed_boundary.lock() else { self.unavailable_witness(); return; };
        if self.case != Case::SignedCancel || !self.permits_mode(wire::Operation::IOSSignedExport)
            || self.claimed.load(Ordering::SeqCst) == 0 || original.is_some()
            || !crate::edit_protocol::token(operation) || !crate::edit_protocol::token(generation) {
            self.unavailable_witness(); return;
        }
        *original = Some((operation.to_owned(), generation.to_owned(), Instant::now()));
    }
    pub(crate) fn unavailable_witness(&self) {
        self.failed.store(true, Ordering::SeqCst);
        if let Some(q) = self.original.get().and_then(Weak::upgrade) { q.fail_with("ios-original-witness"); }
    }
    pub(crate) fn prepare_hold(&self, snapshot: Snapshot) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if !self.holds_finality() || !self.permits() || self.claimed.load(Ordering::SeqCst) == 0
            || hold.snapshot.is_some() || hold.entered || hold.released || !snapshot.facts.held(self.case)
            || !terminal_for(self.case, &snapshot) {
            self.unavailable_witness(); return false;
        }
        hold.snapshot = Some(snapshot); true
    }
    pub(crate) async fn hold_observer(&self, end: Instant) -> bool {
        let receiver = {
            let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
            if !self.permits() || Instant::now() >= end || hold.snapshot.is_none() || hold.entered || hold.released {
                self.unavailable_witness(); return false;
            }
            hold.entered = true; hold.receiver.take()
        };
        let Some(receiver) = receiver else { self.unavailable_witness(); return false; };
        // Same registered final observer; no new worker and no guard over await.
        // The receiver is DATA only. Dropping this future neither closes native
        // resources nor detaches another task; owner STOP still shortens its cut.
        let passed = matches!(tokio::time::timeout_at(end.into(), receiver).await, Ok(Ok(())))
            && Instant::now() < end && self.permits();
        if !passed { self.unavailable_witness(); } passed
    }
    fn held_snapshot(&self) -> Option<Snapshot> {
        let hold = self.hold.try_lock().ok()?;
        (hold.entered && !hold.released && self.permits()).then(|| hold.snapshot.clone()).flatten()
    }
    fn release_hold(&self) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if !self.permits() || !hold.entered || hold.released || hold.snapshot.is_none() {
            self.unavailable_witness(); return false;
        }
        let Some(sender) = hold.sender.take() else { self.unavailable_witness(); return false; };
        hold.released = true;
        if sender.send(()).is_err() { self.unavailable_witness(); return false; }
        true
    }
}

// Literal synthetic fixture DATA. Never an executable generator, fallback
// project, credential source, or substitute for original core/native evidence.
const CONFIG: &[u8] = br#"{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"#;
const CONFIG_SIGNED: &[u8] = br#"{
  "android": {"enabled": false},
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "distributionCertificateSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {"policy": "retain"},
    "teamId": "INERT12345"
  },
  "metadata": {"androidLocales": [], "iosLocales": ["en-US"], "root": "release/store"},
  "projectChecks": {"androidArtifact": [], "iosArtifact": [], "preflight": []},
  "schemaVersion": 1,
  "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
  "source": {"candidateBranch": "main", "productionBranch": "main"},
  "version": {"buildKey": "BUILD_NUMBER", "nameKey": "VERSION_NAME", "source": "version.properties"}
}
"#;
const CONFIG_ANDROID_INPUTS: &[u8] = br#"{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "required",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"#;
const CONFIG_INPUTS: &[u8] = br#"{
  "android": {"enabled": false},
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "distributionCertificateSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {"policy": "retain"},
    "teamId": "INERT12345"
  },
  "metadata": {"androidLocales": [], "iosLocales": ["en-US"], "root": "release/store"},
  "projectChecks": {"androidArtifact": [], "iosArtifact": [], "preflight": []},
  "schemaVersion": 1,
  "services": {"androidFirebase": "disabled", "iosFirebase": "required"},
  "source": {"candidateBranch": "main", "productionBranch": "main"},
  "version": {"buildKey": "BUILD_NUMBER", "nameKey": "VERSION_NAME", "source": "version.properties"}
}
"#;
const CONFIG_PREREQUISITE: &[u8] = br#"{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/usr/bin/false"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"#;
const CONFIG_CANCEL: &[u8] = br#"{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/bin/sleep",
      "30"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"#;
const PROJECT: &[u8] = br#"// !$*UTF8*$!
{
 archiveVersion = 1;
 classes = {};
 objectVersion = 56;
 objects = {
  000000000000000000000001 = {isa = PBXProject; attributes = {BuildIndependentTargetsInParallel = YES; LastUpgradeCheck = 1500;}; buildConfigurationList = 000000000000000000000002; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base); mainGroup = 000000000000000000000003; productRefGroup = 000000000000000000000004; projectDirPath = ""; projectRoot = ""; targets = (000000000000000000000005);};
  000000000000000000000002 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000006); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  000000000000000000000003 = {isa = PBXGroup; children = (000000000000000000000007, 000000000000000000000004, 000000000000000000000008); sourceTree = "<group>";};
  000000000000000000000004 = {isa = PBXGroup; children = (000000000000000000000009); name = Products; sourceTree = "<group>";};
  000000000000000000000005 = {isa = PBXNativeTarget; buildConfigurationList = 00000000000000000000000A; buildPhases = (00000000000000000000000B, 00000000000000000000000C, 00000000000000000000000D); buildRules = (); dependencies = (); name = MRKObserved; productName = MRKObserved; productReference = 000000000000000000000009; productType = "com.apple.product-type.application";};
  000000000000000000000006 = {isa = XCBuildConfiguration; buildSettings = {CLANG_ENABLE_OBJC_ARC = YES; SDKROOT = iphoneos;}; name = Release;};
  000000000000000000000007 = {isa = PBXGroup; children = (00000000000000000000000E, 00000000000000000000000F); path = MRKObserved; sourceTree = "<group>";};
  000000000000000000000008 = {isa = PBXGroup; children = (000000000000000000000010); name = Frameworks; sourceTree = "<group>";};
  000000000000000000000009 = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = MRKObserved.app; sourceTree = BUILT_PRODUCTS_DIR;};
  00000000000000000000000A = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000011); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  00000000000000000000000B = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000012); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000C = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000013); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000D = {isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000E = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = main.m; sourceTree = "<group>";};
  00000000000000000000000F = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>";};
  000000000000000000000010 = {isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = UIKit.framework; path = System/Library/Frameworks/UIKit.framework; sourceTree = SDKROOT;};
  000000000000000000000011 = {isa = XCBuildConfiguration; buildSettings = {
   ARCHS = arm64;
   CODE_SIGNING_ALLOWED = NO;
   CODE_SIGNING_REQUIRED = NO;
   DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
   GCC_GENERATE_DEBUGGING_SYMBOLS = YES;
   INFOPLIST_FILE = MRKObserved/Info.plist;
   IPHONEOS_DEPLOYMENT_TARGET = 15.0;
   PRODUCT_BUNDLE_IDENTIFIER = org.example.mrk.observed;
   PRODUCT_NAME = MRKObserved;
   SKIP_INSTALL = NO;
   STRIP_INSTALLED_PRODUCT = NO;
   SUPPORTED_PLATFORMS = iphoneos;
   TARGETED_DEVICE_FAMILY = "1,2";
  }; name = Release;};
  000000000000000000000012 = {isa = PBXBuildFile; fileRef = 00000000000000000000000E;};
  000000000000000000000013 = {isa = PBXBuildFile; fileRef = 000000000000000000000010;};
 };
 rootObject = 000000000000000000000001;
}
"#;
const SCHEME: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1500" version="1.3">
 <BuildAction parallelizeBuildables="NO" buildImplicitDependencies="NO"><BuildActionEntries>
  <BuildActionEntry buildForTesting="NO" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000005" BuildableName="MRKObserved.app" BlueprintName="MRKObserved" ReferencedContainer="container:MRKObserved.xcodeproj"/>
  </BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="NO"/>
</Scheme>
"#;
const MAIN: &[u8] = br#"#import <UIKit/UIKit.h>
@interface MRKObservedDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation MRKObservedDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UIViewController alloc] init];
    self.window.rootViewController.view.backgroundColor = UIColor.systemBackgroundColor;
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(MRKObservedDelegate.class)); }
}
"#;
const PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>CFBundleDevelopmentRegion</key><string>en</string>
 <key>CFBundleExecutable</key><string>$(EXECUTABLE_NAME)</string>
 <key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
 <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
 <key>CFBundleName</key><string>$(PRODUCT_NAME)</string>
 <key>CFBundlePackageType</key><string>APPL</string>
 <key>CFBundleShortVersionString</key><string>$(MARKETING_VERSION)</string>
 <key>CFBundleVersion</key><string>$(CURRENT_PROJECT_VERSION)</string>
 <key>LSRequiresIPhoneOS</key><true/>
 <key>UILaunchScreen</key><dict/>
 <key>UISupportedInterfaceOrientations</key><array><string>UIInterfaceOrientationPortrait</string></array>
</dict></plist>
"#;
const WORKSPACE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Workspace version="1.0"><FileRef location="self:"/></Workspace>
"#;
pub(super) fn config(case: Case) -> &'static [u8] { match case {
    Case::ToolchainPrerequisite => CONFIG_PREREQUISITE, Case::Cancel => CONFIG_CANCEL,
    Case::SignedRefusal | Case::SignedCancel => CONFIG_SIGNED, Case::SigningInputs => CONFIG_INPUTS,
    Case::AndroidInputs => CONFIG_ANDROID_INPUTS, _ => CONFIG,
} }

const STALE_VERSION: &[u8] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n";
const DIRS: &[(&str, u32, &[&str])] = &[
    ("ios", 0o700, &["MRKObserved", "MRKObserved.xcodeproj"]),
    ("ios/MRKObserved", 0o700, &["Info.plist", "main.m"]),
    ("ios/MRKObserved.xcodeproj", 0o700, &["project.pbxproj", "project.xcworkspace", "xcshareddata"]),
    ("ios/MRKObserved.xcodeproj/project.xcworkspace", 0o700, &["contents.xcworkspacedata"]),
    ("ios/MRKObserved.xcodeproj/xcshareddata", 0o700, &["xcschemes"]),
    ("ios/MRKObserved.xcodeproj/xcshareddata/xcschemes", 0o700, &["MRKObserved.xcscheme"]),
    ("release", 0o755, &["mobile-release.json"]),
];
const ANDROID_DIRS: &[(&str, u32, &[&str])] = &[
    ("app", 0o700, &["build.gradle.kts"]), ("release", 0o755, &["mobile-release.json"]),
];
fn directories(case: Case) -> &'static [(&'static str, u32, &'static [&'static str])] {
    if case.recovery() { &[] } else if case == Case::AndroidInputs { ANDROID_DIRS } else { DIRS }
}
fn files(case: Case, stale: bool) -> Vec<(&'static str, &'static [u8])> {
    let ignore = b"# MRK Mac Aqua user ignore\nuser-output/\n.mobile-release/\n".as_slice();
    if case.recovery() { return vec![(".gitignore", ignore), ("keep.txt", super::KEEP)]; }
    if case == Case::AndroidInputs { return vec![(".gitignore", ignore), ("keep.txt", super::KEEP),
        ("version.properties", super::VERSION), ("release/mobile-release.json", config(case)),
        ("app/build.gradle.kts", super::SOURCE), ("overlap.jks", super::session::JKS)]; }
    let mut files: Vec<(&'static str, &'static [u8])> = vec![
    (".gitignore", b"# MRK Mac Aqua user ignore\nuser-output/\n.mobile-release/\n"),
    ("keep.txt", super::KEEP), ("version.properties", if stale { STALE_VERSION } else { super::VERSION }),
    ("release/mobile-release.json", config(case)), ("ios/MRKObserved.xcodeproj/project.pbxproj", PROJECT),
    ("ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme", SCHEME),
    ("ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata", WORKSPACE),
    ("ios/MRKObserved/main.m", MAIN), ("ios/MRKObserved/Info.plist", PLIST),
];
    if case == Case::SigningInputs { files.push(("overlap.p12", super::session::PFX)); }
    files
}
/// Source originals only. Archive contents remain the real core's retained
/// inventory; the helper performs independent finite post-exit readback.
struct Output { operation: String, archive: bool }
pub(super) struct Fixture {
    case: Case, files: Vec<super::FileFact>, directories: Vec<[u64; 6]>,
    inputs: Option<super::session::Fixture>,
    stale: bool, output: Option<Output>, finalized: bool,
}
impl Fixture {
    pub(super) fn capture(root: &std::path::Path, uid: u32, case: Case) -> Result<Self, ()> {
        let files = files(case, false).into_iter().map(|(path, body)| super::file_fact(&root.join(path), body, uid))
            .collect::<Result<Vec<_>, _>>()?;
        let dirs = directories(case);
        let directories = dirs.iter().map(|(path, mode, entries)| super::directory(&root.join(path), uid, *mode, entries))
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = if case.inputs() { Some(super::session::Fixture::capture(root, uid, case)?) } else { None };
        Ok(Self { case, files, directories, inputs, stale: false, output: None, finalized: false })
    }
    pub(super) fn root_entries(&self) -> Vec<&str> {
        let mut entries = if self.case.recovery() { vec![".gitignore", "keep.txt"] }
            else if self.case == Case::AndroidInputs { vec![".gitignore", "app", "keep.txt", "overlap.jks", "release", "version.properties"] }
            else { vec![".gitignore", "ios", "keep.txt", "release", "version.properties"] };
        if self.case == Case::SigningInputs { entries.push("overlap.p12"); }
        if self.output.is_some() { entries.push(".mobile-release"); } entries
    }
    pub(super) fn source_identity(&self) -> Option<[u64; 6]> { self.directories.first().copied() }
    pub(super) fn release_identity(&self) -> Option<[u64; 6]> { self.directories.get(if self.case == Case::AndroidInputs { 1 } else { 6 }).copied() }
    pub(super) fn ignore(&self) -> super::FileFact { self.files[0].clone() }
    pub(super) fn config(&self) -> Option<super::FileFact> { self.files.get(3).cloned() }
    pub(super) fn verify(&self, root: &std::path::Path, uid: u32) -> Result<(), ()> {
        for ((path, bytes), original) in files(self.case, self.stale).into_iter().zip(&self.files) {
            if &super::file_fact(&root.join(path), bytes, uid)? != original { return Err(()); }
        }
        let dirs = directories(self.case);
        for ((path, mode, entries), original) in dirs.iter().zip(&self.directories) {
            if &super::directory(&root.join(path), uid, *mode, entries)? != original { return Err(()); }
        }
        if let Some(inputs) = &self.inputs { inputs.verify(root, uid)?; }
        if let Some(output) = &self.output {
            super::directory(&root.join(".mobile-release"), uid, 0o700, &["desktop-ios-archive"])?;
            super::directory(&root.join(".mobile-release/desktop-ios-archive"), uid, 0o700, &[&output.operation])?;
            super::directory(&root.join(".mobile-release/desktop-ios-archive").join(&output.operation), uid, 0o700,
                if output.archive { &["archive.xcarchive"] } else { &[] })?;
        }
        Ok(())
    }
    pub(super) fn mutate_version(&mut self, root: &std::path::Path, uid: u32, end: Instant,
        failed: &AtomicBool) -> Result<(), ()> {
        use std::{fs::OpenOptions, io::{Read, Seek, SeekFrom, Write}, os::{fd::AsFd, unix::fs::OpenOptionsExt}};
        let current = || Instant::now() < end && !failed.load(Ordering::SeqCst);
        if self.case != Case::VersionStale || self.stale || self.output.is_some() || self.finalized || !current() { return Err(()); }
        self.verify(root, uid)?;
        let path = root.join("version.properties");
        let mut file = OpenOptions::new().read(true).write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(&path).map_err(|_| ())?;
        let original = &self.files[2];
        let result = (|| {
            if super::identity(&file.metadata().map_err(|_| ())?)? != original.identity
                || super::identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != original.identity { return Err(()); }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
            let mut bytes = Vec::with_capacity(super::VERSION.len() + 1);
            (&mut file).take(super::VERSION.len() as u64 + 1).read_to_end(&mut bytes).map_err(|_| ())?;
            if bytes != super::VERSION || super::identity(&file.metadata().map_err(|_| ())?)? != original.identity { return Err(()); }
            // One literal byte on the prebound original, never replacement,
            // truncation, restoration or a retry after a partial/error return.
            file.seek(SeekFrom::Start((super::VERSION.len() - 2) as u64)).map_err(|_| ())?;
            if !current() || file.write(b"8").map_err(|_| ())? != 1 || !current() { return Err(()); }
            file.sync_all().map_err(|_| ())?;
            let after = super::identity(&file.metadata().map_err(|_| ())?)?;
            if !current() || after[..7] != original.identity[..7]
                || super::identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != after { return Err(()); }
            Ok(after)
        })();
        let closed = nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
        if !closed || !current() { return Err(()); }
        let after = result?;
        let observed = super::file_fact(&path, STALE_VERSION, uid)?;
        if observed.identity != after || !current() { return Err(()); }
        self.files[2] = observed; self.stale = true; self.verify(root, uid)?;
        current().then_some(()).ok_or(())
    }
    pub(super) fn finalize(&mut self, root: &std::path::Path, uid: u32, snapshot: &Snapshot) -> Result<(), ()> {
        if self.finalized || !snapshot.facts.final_for(self.case) || !terminal_for(self.case, snapshot)
            || self.stale != (self.case == Case::VersionStale) { return Err(()); }
        use wire::OutputDisposition as O;
        if self.case.recovery() {
            if snapshot.terminal.disposition.is_some() { return Err(()); }
            self.verify(root, uid)?; self.finalized = true; return Ok(());
        }
        let disposition = snapshot.terminal.disposition.as_ref().ok_or(())?;
        self.output = match disposition.output {
            O::NotCreated => None,
            O::RetainedIncomplete | O::RetainedLocalResult => Some(Output { operation: snapshot.facts.operation_id.clone(),
                archive: disposition.output == O::RetainedLocalResult }),
            O::Unknown => return Err(()),
        };
        self.verify(root, uid)?; self.finalized = true; Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, SignedMode, ReadVersion, VersionRead, Prepare, Review, Acknowledge, Acknowledged,
    MutateVersion, Start, Running, Cancel, Hold, ReleaseHold, Final,
    AccountPrepare, AccountReview, AccountAcknowledge, AccountAcknowledged, AccountStart, AccountRunning, AccountFinal }
#[derive(Clone, Default)]
pub(super) struct Record {
    pending: Option<pending::Record>,
    version_requested: bool, version: Option<Value>, context: Option<wire::Context>,
    version_mutated: bool,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, acknowledged: bool,
    start_requested: bool, start_returned: bool, cancel_requested: bool, cancel_returned: bool,
    status_requested: u16, status_returned: u16, status: Option<wire::Status>,
    prepared: Option<wire::Projection>, held: Option<Snapshot>, held_dom: bool, reciprocal_blocked: bool,
    released: bool, terminal: Option<Snapshot>, final_dom: bool,
    signed_policy: Option<wire::SigningPolicy>, signed_boundary: Option<(String, String)>,
    cancel_dom_stage: Option<wire::Stage>,
    recovery_actions_blocked: bool,
}
fn version_value(case: Case) -> Value {
    json!({"schemaVersion":2,"source":"version.properties","version":{"name":"1.2.3","build":7},
        "observationScope":"single-request-non-atomic","assurance":{"basis":"static-text","projectCodeExecuted":false,
            "toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,
            "writesPerformed":false,"releaseReadiness":"unknown"},
        "savedConfig":{"bytes":config(case).len(),"sha256":super::digest(config(case))},
        "savedVersion":{"bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}})
}
fn context_matches(case: Case, project: &str, context: &wire::Context, signing: Option<&wire::SigningPolicy>) -> bool {
    if context.project_id != project || context.platform != wire::Platform::Ios || Some(context.operation) != case.operation() { return false; }
    if case.recovery() {
        let intent = match context.recovery.as_ref() {
            Some(wire::RecoveryIntent { action: wire::RecoveryAction::Inspect, session: None }) => true,
            Some(wire::RecoveryIntent { action: wire::RecoveryAction::Account, session: Some(token) }) =>
                case == Case::RecoveryPending && crate::edit_protocol::token(token),
            _ => false,
        };
        return context.draft_revision.is_none() && context.baseline_generation.is_none()
            && context.saved_config.is_none() && context.saved_version.is_none() && context.signing.is_none() && signing.is_none()
            && intent;
    }
    let (Some(saved_config), Some(saved_version)) = (&context.saved_config, &context.saved_version) else { return false; };
    context.signing.as_ref() == signing && case.signed() == signing.is_some() && context.recovery.is_none()
        && serde_json::to_value(saved_config).ok() == Some(version_value(case)["savedConfig"].clone())
        && serde_json::to_value(saved_version).ok() == Some(json!({"source":"version.properties","name":"1.2.3","build":7,
            "bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}))
}
fn terminal_for(case: Case, snapshot: &Snapshot) -> bool {
    let t = &snapshot.terminal;
    if Some(t.context.operation) != case.operation() || t.context.platform != wire::Platform::Ios || !t.settled()
        || !context_matches(case, &t.context.project_id, &t.context, t.context.signing.as_ref()) { return false; }
    use wire::{CommandOutcome as C, Outcome as O, Reason as R, OutputDisposition as D};
    if case == Case::RecoveryPending { return pending::terminal_for(snapshot); }
    if case == Case::RecoveryEmpty {
        return t.outcome == O::Complete && t.reason == R::None && t.disposition.is_none() && t.result.is_none()
            && t.activity.archive_activity().is_none() && t.activity.stage == wire::Stage::DisposingWork
            && t.lifetime.stop_observed == wire::CoreStop::None && t.lifetime.profile_calls == 0
            && t.lifetime.commands <= wire::RECOVERY_COMMAND_LIMIT
            && t.report.as_ref().is_some_and(|r| [&r.account, &r.project].into_iter().all(|row| row.as_ref().is_some_and(|row|
                row.status == wire::RecoveryState::Idle && row.session.is_none() && row.next == wire::RecoveryNext::None)));
    }
    if t.report.is_some() { return false; }
    let (Some(activity), Some(disposition)) = (t.activity.archive_activity(), t.disposition.as_ref()) else { return false; };
    let zero = |c: &wire::CommandData| c.outcome == C::Exited && c.exit_code == Some(0);
    let not_dispatched = |c: &wire::CommandData| c.outcome == C::NotDispatched && c.exit_code.is_none();
    let commands = &activity.commands;
    if case.signed() {
        if !commands.export.as_ref().is_some_and(not_dispatched) || !not_dispatched(&commands.archive)
            || commands.prepare.outcome != C::NotConfigured || commands.prepare.exit_code.is_some()
            || t.result.is_some() || t.lifetime.profile_calls > wire::SIGNED_PROFILE_LIMIT
            || t.lifetime.commands > wire::SIGNED_COMMAND_LIMIT { return false; }
        return match case {
            Case::SignedRefusal => t.outcome == O::Failed && t.reason == R::SigningValidationFailed
                && zero(&commands.xcode_version) && zero(&commands.ios_sdk)
                && t.activity.stage == wire::Stage::ValidatingSigning && disposition.output == D::RetainedIncomplete
                && t.lifetime.stop_observed == wire::CoreStop::None
                && activity.findings.iter().any(|f| matches!(f.check, wire::CheckId::SigningMaterial | wire::CheckId::ProfileMaterial)
                    && matches!(f.status, wire::CoreStatus::Fail | wire::CoreStatus::Missing | wire::CoreStatus::Blocked | wire::CoreStatus::Invalid)),
            Case::SignedCancel => t.outcome == O::Cancelled && t.reason == R::Cancelled
                && t.lifetime.stop_observed == wire::CoreStop::Cancelled
                && matches!(disposition.output, D::NotCreated | D::RetainedIncomplete)
                && [&commands.xcode_version, &commands.ios_sdk].into_iter().all(|command|
                    matches!(command.outcome, C::NotDispatched | C::Exited | C::Unknown)),
            _ => false,
        };
    }
    if commands.export.is_some() { return false; }
    match case {
        Case::ToolchainPrerequisite => t.outcome == O::Failed && t.reason == R::CommandFailed
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk)
            && commands.prepare.outcome == C::Exited && commands.prepare.exit_code == Some(1)
            && not_dispatched(&commands.archive) && t.result.is_none() && activity.findings.is_empty()
            && disposition.output == D::RetainedIncomplete,
        Case::VersionStale => t.outcome == O::Refused && t.reason == R::SavedVersionChanged
            && [&commands.xcode_version, &commands.ios_sdk, &commands.prepare, &commands.archive].into_iter().all(not_dispatched)
            && t.result.is_none() && activity.findings.is_empty() && disposition.output == D::NotCreated,
        Case::Cancel => t.outcome == O::Cancelled && t.reason == R::Cancelled
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk)
            // Known original finality does not invent an exit status for a
            // stopped command. Unknown here is result DATA, not custody.
            && matches!(commands.prepare.outcome, C::NotDispatched | C::Exited | C::Unknown)
            && not_dispatched(&commands.archive) && t.result.is_none() && disposition.output == D::RetainedIncomplete,
        Case::UnsignedArchive | Case::Finality => t.outcome == O::Complete && t.reason == R::None
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk) && zero(&commands.archive)
            && commands.prepare.outcome == C::NotConfigured && commands.prepare.exit_code.is_none()
            && activity.selection.as_ref().is_some_and(|s| s.symbols_policy == wire::SymbolsPolicy::Required)
            && t.result.is_some() && disposition.output == D::RetainedLocalResult,
        Case::SigningInputs | Case::AndroidInputs | Case::SignedRefusal | Case::SignedCancel | Case::RecoveryEmpty | Case::RecoveryPending => false,
    }
}
impl Record {
    pub(super) fn new(case: Case) -> Self {
        Self { pending: (case == Case::RecoveryPending).then(pending::Record::default), ..Self::default() }
    }
    fn start_returned_for(&self, status: &wire::Status) -> bool {
        self.pending.as_ref().map_or(self.start_returned, |pair| pair.start_returned_for(status))
    }
    pub(super) fn bind_signing(&mut self, policy: wire::SigningPolicy) -> bool {
        if self.signed_policy.is_some() || self.version_requested || self.prepare_requested || self.start_requested { return false; }
        self.signed_policy = Some(policy); true
    }
    pub(super) fn version_mutated(&mut self) -> bool {
        if self.version_mutated || !self.review_visible || !self.acknowledged || self.start_requested { return false; }
        self.version_mutated = true; true
    }
    fn request(&mut self, case: Case, step: Step, command: Command, value: &Value, project: Option<&str>) -> bool {
        if case == Case::RecoveryPending { return self.pending.as_mut().is_some_and(|pair| pair.request(step, command, value, project)); }
        if self.pending.is_some() { return false; }
        match command {
            Command::Status => {
                if wire::status_request(value).is_err() || self.status_requested >= 64 { return false; }
                self.status_requested += 1; true
            },
            Command::Prepare => {
                if !matches!(step, Step::Prepare | Step::Review) || self.prepare_requested
                    || (case == Case::RecoveryEmpty) != self.version.is_none() { return false; }
                let Ok(input) = wire::prepare(value) else { return false; };
                let context = input.context();
                if !project.is_some_and(|project| context_matches(case, project, &context, self.signed_policy.as_ref())) { return false; }
                self.context = Some(context); self.prepare_requested = true; true
            },
            Command::Start => {
                if !matches!(step, Step::Start | Step::Running) || !self.prepare_returned || !self.review_visible || !self.acknowledged || self.start_requested { return false; }
                let (Ok(input), Some(prepared)) = (wire::start(value), self.prepared.as_ref()) else { return false; };
                if input.operation_id != prepared.operation_id || input.owner_generation != prepared.owner_generation
                    || !input.consent_matches(&prepared.context) { return false; }
                self.start_requested = true; true
            },
            Command::Cancel => {
                if !matches!(case, Case::Cancel | Case::SignedCancel) || !matches!(step, Step::Cancel | Step::Running) || !self.start_requested || self.cancel_requested { return false; }
                let (Ok(input), Some(prepared)) = (wire::cancel(value), self.prepared.as_ref()) else { return false; };
                if input.operation_id != prepared.operation_id || input.owner_generation != prepared.owner_generation { return false; }
                if case == Case::SignedCancel && self.signed_boundary.as_ref() != Some(&(input.operation_id.clone(),input.owner_generation.clone())) { return false; }
                self.cancel_requested = true; true
            },
        }
    }
    fn status(&mut self, status: &wire::Status) -> bool {
        if let Some(pair) = &mut self.pending { return pair.status(status); }
        if wire::status_bytes(status).is_err() { return false; }
        if let Some(op) = &status.operation {
            if self.context.as_ref() != Some(&op.context) || op.phase == wire::Phase::Unknown { return false; }
            if let Some(original) = &self.prepared {
                if original.operation_id != op.operation_id || original.owner_generation != op.owner_generation { return false; }
            } else if !self.prepare_requested || op.phase != wire::Phase::AwaitingConsent || !op.intent_usable { return false; }
            else { self.prepared = Some(op.clone()); }
        } else if self.prepared.is_some() && !self.status.as_ref().is_some_and(|old| status.status_revision < old.status_revision) { return false; }
        if let Some(previous) = &self.status {
            // A real invoke result may arrive after a newer same-owner relay
            // sample. It cannot undo observation or supply a new permission.
            if status.status_revision < previous.status_revision { return true; }
            if status.status_revision == previous.status_revision && status.operation != previous.operation { return false; }
        }
        self.status = Some(status.clone()); true
    }
    fn result(&mut self, command: Command, result: &Result<wire::Status, BridgeError>) -> bool {
        if let Some(pair) = &mut self.pending { return pair.result(command, result); }
        let Ok(status) = result else { return false; };
        let valid = match command {
            Command::Prepare => self.prepare_requested && !self.prepare_returned
                && status.operation.as_ref().is_some_and(|op| op.phase == wire::Phase::AwaitingConsent && op.intent_usable),
            Command::Start => self.start_requested && !self.start_returned,
            Command::Cancel => self.cancel_requested && !self.cancel_returned,
            Command::Status => self.status_returned < self.status_requested,
        };
        if !valid || !self.status(status) { return false; }
        match command { Command::Prepare => self.prepare_returned = true, Command::Start => self.start_returned = true,
            Command::Cancel => self.cancel_returned = true, Command::Status => self.status_returned += 1 }
        true
    }
    fn original(&mut self, case: Case, snapshot: Snapshot) -> bool {
        if case == Case::RecoveryPending { return self.pending.as_mut().is_some_and(|pair| pair.original(snapshot)); }
        let Some(op) = self.status.as_ref().and_then(|s| s.operation.as_ref()) else { return false; };
        if !self.start_requested || !self.start_returned || op.phase != wire::Phase::Terminal || !snapshot.facts.final_for(case)
            || snapshot.facts.operation_id != op.operation_id || snapshot.facts.owner_generation != op.owner_generation
            || snapshot.terminal.context != op.context || op.report != snapshot.terminal.report
            || !terminal_for(case, &snapshot) || op.outcome != Some(snapshot.terminal.outcome)
            || op.reason != snapshot.terminal.reason || op.activity.as_ref() != Some(&snapshot.terminal.activity)
            || op.disposition != snapshot.terminal.disposition || op.result != snapshot.terminal.result { return false; }
        if self.held.as_ref().is_some_and(|held| held.terminal != snapshot.terminal
            || held.facts.operation_id != snapshot.facts.operation_id || held.facts.owner_generation != snapshot.facts.owner_generation) { return false; }
        if let Some(previous) = &self.terminal { return previous == &snapshot; }
        self.terminal = Some(snapshot); true
    }
    pub(super) fn terminal(&self) -> Option<&Snapshot> {
        if let Some(pair) = &self.pending { pair.terminal() } else { self.terminal.as_ref().filter(|_| self.final_dom) }
    }
    pub(super) fn advance(&mut self, step: Step, control: &Control, document: &DocumentBinding) -> Option<Step> {
        if control.case == Case::RecoveryPending { return self.pending.as_ref()?.advance(step); }
        match step {
            Step::VersionRead if self.version.is_none() => None,
            Step::Review if !self.prepare_returned => None,
            Step::Running => {
                if self.terminal.is_some() { return Some(Step::Final); }
                if control.case == Case::Cancel && !self.cancel_requested && self.start_returned
                    && self.status.as_ref().and_then(|s| s.operation.as_ref()).is_some_and(|op|
                        op.phase == wire::Phase::Running && op.stage == Some(wire::Stage::Preparing)) { return Some(Step::Cancel); }
                if control.case == Case::SignedCancel && !self.cancel_requested && self.start_returned {
                    let boundary = control.signed_boundary.try_lock().ok()?.clone();
                    if let Some((operation, generation, observed_at)) = boundary {
                        if !control.permits() || observed_at > Instant::now() || !self.prepared.as_ref().is_some_and(|op|
                            op.operation_id == operation && op.owner_generation == generation) || self.signed_boundary.is_some() {
                            control.unavailable_witness(); return None;
                        }
                        self.signed_boundary = Some((operation, generation)); return Some(Step::Cancel);
                    }
                }
                if control.case.holds_finality() && !self.released {
                    if let Some(snapshot) = control.held_snapshot() {
                        if !self.prepared.as_ref().is_some_and(|op| snapshot.facts.operation_id == op.operation_id
                            && snapshot.facts.owner_generation == op.owner_generation) { control.unavailable_witness(); return None; }
                        if self.held.as_ref().is_some_and(|old| old != &snapshot) { control.unavailable_witness(); return None; }
                        let status = document.environment_diagnostics_status();
                        if !status.as_ref().is_ok_and(|s| !s.capability.available
                            && s.capability.reason == crate::environment_diagnostics_protocol::Availability::Busy) {
                            control.unavailable_witness(); return None;
                        }
                        self.held = Some(snapshot); self.reciprocal_blocked = true; return Some(Step::Hold);
                    }
                }
                None
            },
            Step::ReleaseHold => {
                if !self.held_dom || !self.reciprocal_blocked || self.released || !control.release_hold() {
                    control.unavailable_witness(); return None;
                }
                self.released = true; Some(Step::Running)
            },
            _ => Some(step),
        }
    }
}

/// Inert protocol/comparison regressions in the existing native test target.
/// No Observation constructor, diagnostic writer, native owner or task starts;
/// these synthetic values never leave the checks as an observed receipt.
pub(super) fn data_checks() -> bool {
    for case in Case::ALL {
        if Case::parse(OsStr::new(case.name())) != Some(case)
            || Case::parse(OsStr::new(&format!("{}-other", case.name()))).is_some() { return false; }
    }
    if Case::parse(OsStr::new("first-save")).is_some() || Case::parse(OsStr::new("IOS-UNSIGNED-ARCHIVE")).is_some() { return false; }
    let control = Control::new(Case::UnsignedArchive);
    let document = Arc::new(()); let owner = Arc::new(()); let foreign = Arc::new(());
    let token = Admission { control: control.clone(), document: Arc::downgrade(&document), owner: Arc::downgrade(&owner) };
    if !token.document_matches(&document) || token.document_matches(&foreign) || control.permits()
        || control.claim().is_ok() || token.consume(&owner).is_ok() { return false; }
    let dead = Arc::downgrade(&foreign); drop(foreign);
    let token = Admission { control: control.clone(), document: dead, owner: Arc::downgrade(&owner) };
    if token.document_matches(&document) || token.consume(&owner).is_ok() || control.claimed.load(Ordering::SeqCst) != 0 { return false; }

    let case = Case::UnsignedArchive;
    let observed = version_value(case);
    let input = json!({"projectId":"inert-ios-parser","draftRevision":1,"baselineGeneration":1,
        "savedConfig":observed["savedConfig"],"savedVersion":{"source":"version.properties","name":"1.2.3","build":7,
            "bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}});
    let Ok(preparation) = wire::prepare(&input) else { return false; };
    let context = preparation.context();
    if !context_matches(case, "inert-ios-parser", &context, None) || context_matches(Case::Cancel, "inert-ios-parser", &context, None)
        || context_matches(case, "foreign-project", &context, None) { return false; }
    let mut old_pair = context.clone();
    let Some(old_version) = old_pair.saved_version.as_mut() else { return false; }; old_version.build = 8;
    if context_matches(case, "inert-ios-parser", &old_pair, None) { return false; }
    let mut missing_version = context.clone(); missing_version.saved_version = None;
    let mut missing_config = context.clone(); missing_config.saved_config = None;
    if context_matches(case, "inert-ios-parser", &missing_version, None)
        || context_matches(case, "inert-ios-parser", &missing_config, None) { return false; }
    let operation = "a".repeat(32); let generation = "b".repeat(32);
    let prepared = wire::Projection { operation_id: operation.clone(), owner_generation: generation.clone(), context: context.clone(),
        phase: wire::Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: wire::Reason::None,
        stage: None, activity: None, disposition: None, result: None, report: None };
    let mut status = wire::Status { schema_version: 1, status_revision: 1, availability: wire::Availability::Busy, operation: Some(prepared) };
    let mut record = Record::default();
    if record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser")) { return false; }
    record.version = Some(observed);
    if !record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser"))
        || record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser"))
        || !record.result(Command::Prepare, &Ok(status.clone()))
        || record.result(Command::Prepare, &Ok(status.clone())) { return false; }
    let start = json!({"operationId":operation,"ownerGeneration":generation,"consentVersion":wire::CONSENT});
    if record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser")) { return false; }
    record.review_visible = true; record.acknowledged = true;
    let mut other = start.clone(); other["ownerGeneration"] = json!("c".repeat(32));
    if record.request(case, Step::Start, Command::Start, &other, Some("inert-ios-parser"))
        || !record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser"))
        || record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser")) { return false; }

    let mut value = wire::tests::complete();
    value["context"] = serde_json::to_value(&context).unwrap();
    value["result"]["usedConfig"] = value["context"]["savedConfig"].clone();
    value["result"]["usedVersion"] = value["context"]["savedVersion"].clone();
    value["activity"]["selection"] = json!({"containerKind":"project","container":"ios/MRKObserved.xcodeproj",
        "scheme":"MRKObserved","configuration":"Release","bundleId":super::APP_ID,"symbolsPolicy":"required","preparationConfigured":false});
    let Ok(terminal) = wire::terminal(&value, &context, &operation) else { return false; };
    let facts = OriginalFacts { operation_id: operation, owner_generation: generation,
        inspection_joined: true, acquisition_joined: true, attempted: true, child_waited_success: true,
        stdin_closed: true, stdout_eof_closed: true, stderr_eof_closed: true, io_joined: true, core_lifetime_settled: true,
        runtime_ledger_settled: true, tools_ledger_settled: true, native_settlement_joined: true, native_integrity: true,
        driver_joined: true, manager_joined: true, observer_joined: true, watchdog_joined: true,
        retired_before_cutoff: true, active_retained: false, resource_unknown: false, work_ms: 300_000, hard_ms: 310_000,
        cleanup_ms: None, material_loan_retired: None, material_loan_present: None };
    if !facts.final_for(case) || facts.held(case) { return false; }
    let held = OriginalFacts { observer_joined: false, watchdog_joined: false, retired_before_cutoff: false,
        active_retained: true, ..facts.clone() };
    if !held.held(Case::Finality) || held.held(case) || held.final_for(Case::Finality) { return false; }
    let mutations: &[fn(&mut OriginalFacts)] = &[
        |f| f.inspection_joined = false, |f| f.acquisition_joined = false, |f| f.child_waited_success = false,
        |f| f.stdin_closed = false, |f| f.stdout_eof_closed = false, |f| f.stderr_eof_closed = false, |f| f.io_joined = false,
        |f| f.core_lifetime_settled = false, |f| f.runtime_ledger_settled = false, |f| f.tools_ledger_settled = false,
        |f| f.native_settlement_joined = false, |f| f.native_integrity = false, |f| f.driver_joined = false,
        |f| f.manager_joined = false, |f| f.resource_unknown = true, |f| f.work_ms += 1, |f| f.hard_ms += 1,
    ];
    for mutate in mutations {
        let mut late = facts.clone(); mutate(&mut late);
        let mut incomplete = held.clone(); mutate(&mut incomplete);
        if late.final_for(case) || incomplete.held(Case::Finality) { return false; }
    }
    let snapshot = Snapshot { facts, terminal };
    if !terminal_for(case, &snapshot) || !terminal_for(Case::Finality, &snapshot)
        || [Case::ToolchainPrerequisite, Case::VersionStale, Case::Cancel].into_iter().any(|case| terminal_for(case, &snapshot)) { return false; }
    // The additive signed/recovery wire cannot widen this unsigned observer.
    for mode in [wire::Operation::IOSSignedExport, wire::Operation::IOSLocalRecovery] {
        let mut other = snapshot.clone(); other.terminal.context.operation = mode;
        if context_matches(case, "inert-ios-parser", &other.terminal.context, None)
            || Case::ALL.into_iter().any(|case| terminal_for(case, &other)) { return false; }
    }
    let mut missing_disposition = snapshot.clone(); missing_disposition.terminal.disposition = None;
    let mut missing_activity = snapshot.clone();
    let Ok(recovery_activity) = serde_json::from_value(json!({"stage":"disposing-work"})) else { return false; };
    missing_activity.terminal.activity = recovery_activity;
    if terminal_for(case, &missing_disposition) || terminal_for(case, &missing_activity) { return false; }
    // A valid core terminal is insufficient before original status publication.
    if record.original(case, snapshot.clone()) { return false; }
    let op = status.operation.as_mut().unwrap();
    op.phase = wire::Phase::Terminal; op.intent_usable = false; op.outcome = Some(snapshot.terminal.outcome);
    op.stage = Some(snapshot.terminal.activity.stage); op.activity = Some(snapshot.terminal.activity.clone());
    op.disposition = snapshot.terminal.disposition.clone(); op.result = snapshot.terminal.result.clone();
    status.status_revision += 1;
    if !record.result(Command::Start, &Ok(status.clone())) { return false; }
    let mut foreign = snapshot.clone(); foreign.facts.owner_generation = "c".repeat(32);
    let mut wrong_context = snapshot.clone(); wrong_context.terminal.context.project_id = "foreign-project".to_owned();
    let mut provisional = snapshot.clone(); provisional.facts = held.clone();
    if record.original(case, foreign) || record.original(case, wrong_context) || record.original(case, provisional)
        || !record.original(case, snapshot.clone()) || record.terminal().is_some() { return false; }
    let mut held_record = record.clone(); held_record.held = Some(Snapshot { facts: held, terminal: snapshot.terminal.clone() });
    if !held_record.original(Case::Finality, snapshot.clone()) { return false; }
    held_record.held.as_mut().unwrap().terminal.activity.stage = wire::Stage::Inspecting;
    !held_record.original(Case::Finality, snapshot.clone()) && current_data_checks(&snapshot) && pending::data_checks(&snapshot)
}

fn current_data_checks(unsigned: &Snapshot) -> bool {
    // Comparison DATA only. Neither these typed values nor their reports are
    // installed in Control/Observation or returned as native observations.
    let facts = OriginalFacts { work_ms: 120_000, hard_ms: 250_000, cleanup_ms: Some(240_000),
        material_loan_present: Some(false), material_loan_retired: Some(true), ..unsigned.facts.clone() };
    if [Case::SignedRefusal, Case::SignedCancel, Case::RecoveryEmpty].into_iter().any(|case| !facts.final_for(case))
        || facts.final_for(Case::UnsignedArchive) || facts.final_for(Case::SigningInputs) { return false; }
    let held = OriginalFacts { observer_joined: false, watchdog_joined: false, retired_before_cutoff: false,
        active_retained: true, material_loan_present: Some(true), material_loan_retired: Some(false), ..facts.clone() };
    if !held.held(Case::SignedRefusal) || held.held(Case::SignedCancel) || held.held(Case::Finality) { return false; }
    let mutations: &[fn(&mut OriginalFacts)] = &[|f| f.cleanup_ms = None, |f| f.cleanup_ms = Some(240_001),
        |f| f.material_loan_retired = None, |f| f.material_loan_present = None,
        |f| f.work_ms = 300_000, |f| f.hard_ms = 310_000];
    for mutate in mutations {
        let mut final_facts = facts.clone(); mutate(&mut final_facts);
        let mut held_facts = held.clone(); mutate(&mut held_facts);
        if final_facts.final_for(Case::SignedRefusal) || held_facts.held(Case::SignedRefusal) { return false; }
    }
    let mut outstanding = facts.clone(); outstanding.material_loan_present = Some(true);
    let mut unretired = facts.clone(); unretired.material_loan_retired = Some(false);
    if outstanding.final_for(Case::SignedCancel) || unretired.final_for(Case::RecoveryEmpty) { return false; }
    let policy = wire::SigningPolicy { team_id: "INERT12345".into(), distribution_certificate_sha256: "c".repeat(64),
        assignments: ["apple-p12", "apple-profile"].into_iter().enumerate().map(|(i,kind)| wire::SigningAssignment {
            kind: kind.into(), record_id: (i + 1).to_string().repeat(32), record_revision: 1, context_revision: 1 }).collect() };
    let observed = version_value(Case::SignedRefusal);
    let input = json!({"projectId":"inert-ios-parser","draftRevision":1,"baselineGeneration":1,
        "savedConfig":observed["savedConfig"],"savedVersion":unsigned.terminal.context.saved_version,"signing":policy});
    let Ok(preparation) = wire::prepare(&input) else { return false; };
    let context = preparation.context();
    if !context_matches(Case::SignedRefusal, "inert-ios-parser", &context, Some(&policy))
        || context_matches(Case::UnsignedArchive, "inert-ios-parser", &context, Some(&policy))
        || context_matches(Case::SignedRefusal, "inert-ios-parser", &context, None) { return false; }
    let mut foreign = policy.clone(); foreign.assignments[0].record_id = "d".repeat(32);
    if context_matches(Case::SignedRefusal, "inert-ios-parser", &context, Some(&foreign)) { return false; }
    let mut value = match serde_json::to_value(&unsigned.terminal) { Ok(value) => value, Err(_) => return false };
    value["context"] = json!(context); value["outcome"] = json!("failed"); value["reason"] = json!("signing-validation-failed");
    value["activity"]["stage"] = json!("validating-signing"); value["activity"]["selection"]["symbolsPolicy"] = json!("retain");
    for role in ["archive", "export"] { value["activity"]["commands"][role] = json!({"outcome":"not-dispatched","exitCode":null}); }
    value["activity"]["findings"] = json!([{"check":"signing-material","status":"FAIL"}]);
    value["result"] = Value::Null; value["disposition"]["output"] = json!("retained-incomplete");
    value["lifetime"]["commands"] = json!(2);
    for field in ["signingClosed", "buildInputsClosed", "materialRetired"] { value["lifetime"][field] = json!(true); }
    let Ok(terminal) = wire::terminal(&value, &context, &facts.operation_id) else { return false; };
    let refusal = Snapshot { facts: facts.clone(), terminal };
    if !terminal_for(Case::SignedRefusal, &refusal) || terminal_for(Case::SignedCancel, &refusal) { return false; }
    let mut unsupported = value.clone(); unsupported["activity"]["findings"] = json!([]);
    if wire::terminal(&unsupported, &context, &facts.operation_id).is_ok_and(|terminal|
        terminal_for(Case::SignedRefusal, &Snapshot { facts: facts.clone(), terminal })) { return false; }
    value["outcome"] = json!("cancelled"); value["reason"] = json!("cancelled");
    value["lifetime"]["stopObserved"] = json!("cancelled");
    let Ok(terminal) = wire::terminal(&value, &context, &facts.operation_id) else { return false; };
    if !terminal_for(Case::SignedCancel, &Snapshot { facts: facts.clone(), terminal }) { return false; }
    let mut cancel = Record::default(); cancel.start_requested = true;
    cancel.prepared = Some(wire::Projection { operation_id: facts.operation_id.clone(), owner_generation: facts.owner_generation.clone(),
        context: context.clone(), phase: wire::Phase::Running, intent_usable: false, outcome: None, reason: wire::Reason::None,
        stage: Some(wire::Stage::InputsBound), activity: None, disposition: None, result: None, report: None });
    let request = json!({"operationId":facts.operation_id,"ownerGeneration":facts.owner_generation});
    if cancel.request(Case::SignedCancel, Step::Cancel, Command::Cancel, &request, Some("inert-ios-parser")) { return false; }
    cancel.signed_boundary = Some((facts.operation_id.clone(), facts.owner_generation.clone()));
    let mut wrong = request.clone(); wrong["ownerGeneration"] = json!("f".repeat(32));
    if cancel.request(Case::SignedCancel, Step::Cancel, Command::Cancel, &wrong, Some("inert-ios-parser"))
        || !cancel.request(Case::SignedCancel, Step::Cancel, Command::Cancel, &request, Some("inert-ios-parser"))
        || cancel.request(Case::SignedCancel, Step::Cancel, Command::Cancel, &request, Some("inert-ios-parser"))
        || cancel.dom(Case::SignedCancel, Step::Cancel, &json!({"state":"ready","stageAtClick":"accepted"})).is_ok()
        || cancel.dom(Case::SignedCancel, Step::Cancel, &json!({"state":"ready","stageAtClick":"validating-signing"})) != Ok(Some(Step::Running))
        || cancel.cancel_dom_stage != Some(wire::Stage::ValidatingSigning) { return false; }
    let Ok(recovery) = wire::prepare(&json!({"projectId":"inert-ios-parser","recovery":{"action":"inspect"}})) else { return false; };
    let recovery = recovery.context();
    if !context_matches(Case::RecoveryEmpty, "inert-ios-parser", &recovery, None)
        || context_matches(Case::SignedCancel, "inert-ios-parser", &recovery, None) { return false; }
    let mut lifetime = value["lifetime"].clone(); lifetime["commands"] = json!(0);
    lifetime["commandDispatched"] = json!(false); lifetime["stopObserved"] = json!("none");
    let idle = json!({"status":"idle","session":null,"next":"none"});
    let mut result = json!({"schemaVersion":1,"context":recovery,"outcome":"complete","reason":"none",
        "activity":{"stage":"disposing-work"},"lifetime":lifetime,
        "report":{"schemaVersion":1,"scope":"local-ios-recovery","account":idle,"project":idle,"limitations":wire::RECOVERY_LIMITATIONS}});
    let Ok(terminal) = wire::terminal(&result, &recovery, &facts.operation_id) else { return false; };
    if !terminal_for(Case::RecoveryEmpty, &Snapshot { facts: facts.clone(), terminal }) { return false; }
    result["report"]["account"] = json!({"status":"pending","session":"d".repeat(32),"next":"ordinary"});
    let Ok(terminal) = wire::terminal(&result, &recovery, &facts.operation_id) else { return false; };
    if terminal_for(Case::RecoveryEmpty, &Snapshot { facts, terminal }) { return false; }
    let document = Arc::new(());
    for case in Case::ALL {
        let control = Control::new(case);
        let token = SessionRegistration { control: control.clone(), document: Arc::downgrade(&document) };
        if token.consume(&document).is_ok() || control.session_registered.load(Ordering::SeqCst)
            || [wire::Operation::IOSUnsignedArchive, wire::Operation::IOSSignedExport, wire::Operation::IOSLocalRecovery]
                .into_iter().any(|mode| control.permits_mode(mode)) { return false; }
    }
    // Exercise the actual one-use identity transition without a native owner,
    // original Observation, availability marker or permission to consume it.
    let wrong = Arc::new(());
    for case in [Case::AndroidInputs, Case::SigningInputs, Case::SignedRefusal, Case::SignedCancel] {
        let control = Control::new(case);
        let registration = SessionRegistration { control: control.clone(), document: Arc::downgrade(&document) };
        if registration.control.case != case || registration.claim_original(&wrong)
            || control.session_registered.load(Ordering::SeqCst) || !registration.claim_original(&document)
            || registration.claim_original(&document) || control.permits() { return false; }
        // Even a correct already-claimed identity is not authority without
        // the actual original observation and every unchanged consume gate.
        if registration.consume(&document).is_ok() { return false; }
    }
    let control = Control::new(Case::SigningInputs);
    let registration = SessionRegistration { control: control.clone(), document: Arc::downgrade(&document) };
    if registration.claim_original(&wrong) || control.session_registered.load(Ordering::SeqCst)
        || !registration.claim_original(&document) || registration.claim_original(&document)
        || control.normal_session_registered() || control.permits() { return false; }
    // DATA-only history model. No original Observation, native owner or
    // positive execution permit is constructed by this contract. The source
    // contract separately binds the returned marker to the actual ? return.
    let owner = Arc::new(());
    if control.document.set(Arc::downgrade(&document)).is_err() || control.owner.set(Arc::downgrade(&owner)).is_err()
        || control.normal_selection_observed.set(()).is_err() || control.normal_session_registered()
        || control.normal_session_registration_returned.set(()).is_err() || !control.normal_session_registered()
        || control.permits() { return false; }
    let dead = Arc::downgrade(&document); drop(document); drop(owner);
    if control.document.get().and_then(Weak::upgrade).is_some() || control.owner.get().and_then(Weak::upgrade).is_some()
        || control.permits() || !control.normal_session_registered() { return false; }
    let control = Control::new(Case::SigningInputs);
    let registration = SessionRegistration { control: control.clone(), document: dead };
    if registration.claim_original(&wrong) || control.session_registered.load(Ordering::SeqCst) { return false; }
    true
}

pub(super) fn snapshot_failure(value: &Value, root: &std::path::Path, case: Case, base: &Value) -> Option<&'static str> {
    if case == Case::AndroidInputs { return super::snapshot_value_failure_bytes(value, root, true, base, config(case)); }
    let config_value = &value["config"]; let hints = &value["discovery"]["hints"];
    if value["root"].as_str() != root.to_str() { return Some("snapshot-value-root"); }
    if value["observationScope"] != "single-request-non-atomic" { return Some("snapshot-value-scope"); }
    if config_value["path"] != "release/mobile-release.json" { return Some("snapshot-config-path"); }
    if !super::assurance(value, "static-text") { return Some("snapshot-value-assurance"); }
    if !value["issues"].as_array().is_some_and(Vec::is_empty) { return Some("snapshot-value-issues"); }
    if case.recovery() {
        if hints != &json!({}) { return Some("ios-fixture-contract"); }
        if value["discovery"]["partial"] != false || value["discovery"]["state"] != "unverified" { return Some("snapshot-discovery-state"); }
        if config_value["state"] != "missing" || !config_value["data"].is_null() || !config_value["content"].is_null()
            || !config_value["issues"].as_array().is_some_and(|rows| rows.len() == 1 && rows[0]["code"] == "config.missing") {
            return Some("snapshot-config-state");
        }
        return None;
    }
    if !hints["android"].is_null() || hints["ios"]["projects"] != json!(["ios/MRKObserved.xcodeproj"])
        || hints["ios"]["workspaces"] != json!([]) || hints["ios"]["schemes"] != json!(["MRKObserved"])
        || hints["ios"]["bundleIds"] != json!([super::APP_ID]) || hints["ios"]["bundleId"] != super::APP_ID {
        return Some("ios-fixture-contract");
    }
    if hints["versionSource"] != "version.properties" || hints["versionNameKey"] != "VERSION_NAME"
        || hints["versionBuildKey"] != "BUILD_NUMBER" { return Some("snapshot-hints-version"); }
    if value["discovery"]["partial"] != false || value["discovery"]["state"] != "unverified" {
        return Some("snapshot-discovery-state");
    }
    if config_value["state"] != "format-valid" { return Some("snapshot-config-state"); }
    if config_value["data"] != *base { return Some("snapshot-config-data"); }
    if config_value["content"] != json!({"bytes":config(case).len(),"sha256":super::digest(config(case))}) {
        return Some("snapshot-config-content");
    }
    if !config_value["issues"].as_array().is_some_and(Vec::is_empty) { return Some("snapshot-config-issues"); }
    None
}

impl Observation {
    pub(crate) fn attach_ios(self: &Arc<Self>, document: &DocumentBinding, owner: &IOSArchiveOwner) -> Result<(), BridgeError> {
        match &self.ios { Some(control) => control.attach(self, document, owner), None => Ok(()) }
    }
    pub(crate) fn release_version_request(&self, value: &Value) {
        let Some(control) = &self.ios else { return; };
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !matches!(r.step, super::Step::Ios(Step::ReadVersion | Step::VersionRead))
            || r.project.as_ref().map(|p| json!({"projectId":p.id})).as_ref() != Some(value) {
            self.fail_with("ios-version-contract"); return;
        }
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-version-contract"); return; };
        if ios.version_requested || ios.version.is_some() || !control.permits() { self.fail_with("ios-version-contract"); return; }
        ios.version_requested = true;
    }
    pub(crate) fn release_version(&self, result: &Result<crate::release_version_protocol::Observation, BridgeError>) {
        let Some(control) = &self.ios else { return; };
        let Some(mut r) = self.record() else { return; };
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-version-contract"); return; };
        let value = result.as_ref().ok().and_then(|value| serde_json::to_value(value).ok());
        if !self.timely() || !ios.version_requested || ios.version.is_some() || value != Some(version_value(control.case)) {
            self.fail_with("ios-version-contract"); return;
        }
        ios.version = value;
    }
    pub(crate) fn ios_request(&self, command: Command, value: &Value) {
        let Some(control) = &self.ios else { return; };
        if control.case.input_only() {
            if !self.timely() || command != Command::Status || wire::status_request(value).is_err() { self.fail_with("ios-request-contract"); }
            return;
        }
        let Some(mut r) = self.record() else { return; };
        let step = match r.step { super::Step::Ios(step) => step, _ if command == Command::Status => Step::Navigate,
            _ => { self.fail_with("ios-request-contract"); return; } };
        let project = r.project.as_ref().map(|p| p.id.clone());
        if !self.timely() || !r.ios_record.as_mut().is_some_and(|ios| ios.request(control.case, step, command, value, project.as_deref())) {
            self.fail_with("ios-request-contract");
        }
    }
    pub(crate) fn ios_result(&self, command: Command, result: &Result<wire::Status, BridgeError>) {
        if self.ios.is_none() { return; }
        if self.ios.as_ref().is_some_and(|c| c.case.input_only()) {
            if !self.timely() || command != Command::Status || !result.as_ref().is_ok_and(|s| s.operation.is_none() && wire::status_bytes(s).is_ok()) {
                self.fail_with("ios-status-contract");
            }
            return;
        }
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.ios_record.as_mut().is_some_and(|ios| ios.result(command, result)) {
            self.fail_with("ios-status-contract");
        }
    }
    pub(crate) fn ios_status(&self, status: &wire::Status, owner: &IOSArchiveOwner) {
        let Some(control) = &self.ios else { return; };
        if control.case.input_only() {
            if !self.timely() || status.operation.is_some() || wire::status_bytes(status).is_err() { self.fail_with("ios-status-contract"); }
            return;
        }
        // Read the actual original owner without holding this observer Record.
        // Busy native guards yield no sample, never a guessed join or fallback.
        let terminal = status.operation.as_ref().is_some_and(|op| op.phase == wire::Phase::Terminal);
        let snapshot = terminal.then(|| owner.installed_ios_snapshot()).flatten().filter(|snapshot|
            status.operation.as_ref().is_some_and(|op| op.operation_id == snapshot.facts.operation_id
                && op.owner_generation == snapshot.facts.owner_generation));
        let Some(mut r) = self.record() else { return; };
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-status-contract"); return; };
        if !self.timely() || !ios.status(status) { self.fail_with("ios-status-contract"); return; }
        if terminal && ios.start_returned_for(status) {
            // A transient borrow refusal can be retried by this SAME ordinary
            // relay. It is not positive evidence and never changes the cutoff.
            if let Some(snapshot) = snapshot {
                if !ios.original(control.case, snapshot) { self.fail_with("ios-finality-contract"); }
            }
        }
    }
}

pub(super) fn script(case: Case, step: Step) -> Option<&'static str> {
    if case == Case::RecoveryPending { return pending::script(step); }
    if case == Case::RecoveryEmpty { return recovery_script(step); }
    if case.signed() {
        match step {
            Step::SignedMode => return Some(r#"const r=ios();if(!r)return wait();const f=r.querySelector('fieldset.session-context'),radios=f?.querySelectorAll('input[type="radio"]');
                if(!f||!radios||radios.length!==2||f.disabled)return wait();if(!radios[0].checked||radios[1].checked||!text(f).includes('Sign and export IPA'))throw 0;
                show(radios[1]);radios[1].click();return ready();"#),
            Step::Review => return Some(r#"const r=ios();if(!r)return wait();if(r.dataset.phase!=='awaiting-consent')return wait();
                const check=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),start=r.querySelector('[data-mrk-ios-archive-action="start"]');
                if(!check||!start)return wait();show(check);return {state:'ready',checked:check.checked,startAvailable:!start.disabled,
                    identityVisible:text(r).includes('org.example.mrk.observed')&&text(r).includes('ios/MRKObserved.xcodeproj')
                        &&text(r).includes('scheme MRKObserved')&&text(r).includes('saved version 1.2.3')&&text(r).includes('build 7')
                        &&text(r).includes('INERT12345')&&text(r).includes('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc')
                        &&text(r).includes('2 exact session input revisions.')&&text(start)==='Sign and export local IPA'};"#),
            Step::Cancel => return Some(r#"const r=ios();if(!r)return wait();if(r.dataset.phase==='terminal')throw 0;
                const b=r.querySelector('[data-mrk-ios-archive-action="cancel"]');if(!b||b.disabled||!['running','stopping'].includes(r.dataset.phase))return wait();
                const stage=r.dataset.stage;show(b);b.click();return {state:'ready',stageAtClick:stage};"#),
            Step::Hold => return Some(r#"const r=ios();if(!r)return wait();if(!['running','stopping'].includes(r.dataset.phase)||r.dataset.stage!=='validating-signing')return wait();
                const read=r.querySelector('[data-mrk-ios-archive-action="observe-version"]'),review=r.querySelector('[data-mrk-ios-archive-action="review"]');
                const refresh=[...r.querySelectorAll('button')].find(b=>text(b)==='Refresh saved configuration');if(!read||!review||!refresh)return wait();show(r);
                return {state:'ready',publicSuccessHidden:r.dataset.outcome===''&&!r.querySelector('.offline-report'),
                    readBlocked:read.disabled,reviewBlocked:review.disabled,refreshBlocked:refresh.disabled};"#),
            _ => {},
        }
    }
    Some(match step {
    Step::Navigate => "return nav('Releases');",
    Step::ReadVersion => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="observe-version"]');
        if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
    Step::VersionRead => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="review"]');
        const v=[...r.querySelectorAll(':scope > p')].find(p=>text(p).startsWith('Saved version '));if(!v||!b||b.disabled)return wait();show(v);
        return {state:'ready',version:text(v),reviewAvailable:true};"#,
    Step::Prepare => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="review"]');
        if(!b||b.disabled)return wait();if(r.dataset.phase!=='idle')throw 0;show(b);b.click();return ready();"#,
    Step::Review => r#"const r=ios();if(!r)return wait();if(r.dataset.phase!=='awaiting-consent')return wait();
        const check=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),start=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!check||!start)return wait();show(check);return {state:'ready',checked:check.checked,startAvailable:!start.disabled,
            identityVisible:text(r).includes('org.example.mrk.observed')&&text(r).includes('ios/MRKObserved.xcodeproj')
                &&text(r).includes('scheme MRKObserved')&&text(r).includes('saved version 1.2.3')&&text(r).includes('build 7')};"#,
    Step::Acknowledge => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]');
        if(!c||c.disabled)return wait();if(c.type!=='checkbox'||c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(c);c.click();return ready();"#,
    Step::Acknowledged => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!c||!b||!c.checked||b.disabled)return wait();show(b);return {state:'ready',checked:c.checked,startAvailable:!b.disabled};"#,
    Step::Start => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!c||!b||b.disabled)return wait();if(!c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(b);b.click();return ready();"#,
    Step::Cancel => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="cancel"]');
        if(!b||b.disabled||r.dataset.phase!=='running'||r.dataset.stage!=='preparing')return wait();show(b);b.click();return ready();"#,
    Step::Hold => r#"const r=ios();if(!r)return wait();if(!['running','stopping'].includes(r.dataset.phase)||r.dataset.stage!=='disposing-work')return wait();
        const read=r.querySelector('[data-mrk-ios-archive-action="observe-version"]'),review=r.querySelector('[data-mrk-ios-archive-action="review"]');
        const refresh=[...r.querySelectorAll('button')].find(b=>text(b)==='Refresh saved configuration');if(!read||!review||!refresh)return wait();show(r);
        return {state:'ready',publicSuccessHidden:r.dataset.outcome===''&&!r.querySelector('.offline-report'),
            readBlocked:read.disabled,reviewBlocked:review.disabled,refreshBlocked:refresh.disabled};"#,
    Step::Final => r#"const r=ios();if(!r||r.dataset.phase!=='terminal')return wait();const p=r.querySelector('.session-progress'),report=r.querySelector('.offline-report');
        if(!p)return wait();show(p);return {state:'ready',phase:r.dataset.phase,outcome:r.dataset.outcome,
            commands:[...p.querySelectorAll(':scope > ul > li')].map(text),resultPresent:!!report,
            archive:report?text(report.querySelector('p > code')):null};"#,
    Step::SignedMode | Step::Running | Step::MutateVersion | Step::ReleaseHold
        | Step::AccountPrepare | Step::AccountReview | Step::AccountAcknowledge | Step::AccountAcknowledged
        | Step::AccountStart | Step::AccountRunning | Step::AccountFinal => return None,
}) }
fn recovery_script(step: Step) -> Option<&'static str> { Some(match step {
    Step::Navigate => "return nav('Recovery');",
    Step::Prepare => r#"const r=recovery();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-recovery-action="review-inspect"]');
        if(!b||b.disabled)return wait();if(r.dataset.phase!=='idle')throw 0;show(b);b.click();return ready();"#,
    Step::Review => r#"const r=recovery();if(!r||r.dataset.phase!=='awaiting-consent')return wait();
        const review=r.querySelector('[aria-label="Confirm this exact local recovery action"]'),check=r.querySelector('[data-mrk-ios-recovery-action="acknowledge"]'),start=r.querySelector('[data-mrk-ios-recovery-action="start"]');
        if(!review||!check||!start)return wait();show(review);return {state:'ready',checked:check.checked,startAvailable:!start.disabled,
            identityVisible:text(review).includes('Inspect account and project state once?')&&text(start)==='Inspect local state once'&&!review.querySelector('code')};"#,
    Step::Acknowledge => r#"const r=recovery();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-recovery-action="acknowledge"]');
        if(!c||c.disabled)return wait();if(c.type!=='checkbox'||c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(c);c.click();return ready();"#,
    Step::Acknowledged => r#"const r=recovery();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-recovery-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-recovery-action="start"]');
        if(!c||!b||!c.checked||b.disabled)return wait();show(b);return {state:'ready',checked:c.checked,startAvailable:!b.disabled};"#,
    Step::Start => r#"const r=recovery();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-recovery-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-recovery-action="start"]');
        if(!c||!b||b.disabled)return wait();if(!c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(b);b.click();return ready();"#,
    Step::Final => r#"const r=recovery();if(!r||r.dataset.phase!=='terminal')return wait();const p=r.querySelector('.session-progress'),report=r.querySelector('[aria-label="Original native local recovery report"]');
        if(!p||!report)return wait();const rows=[...report.querySelectorAll(':scope > div')];if(rows.length!==2)throw 0;show(p);show(report);
        return {state:'ready',phase:r.dataset.phase,outcome:[...p.querySelectorAll(':scope > p')].filter(p=>text(p).startsWith('Operation outcome:')).map(text),
            rows:rows.map(row=>({heading:text(row.querySelector('h4')),sessionVisible:!!row.querySelector('code'),
                recoveryButton:text(row.querySelector('button')),recoveryBlocked:row.querySelector('button')?.disabled===true})),
            artifactResultPresent:!!r.querySelector('.offline-report')};"#,
    _ => return None,
}) }
impl Record {
    pub(super) fn dom(&mut self, case: Case, step: Step, value: &Value) -> Result<Option<Step>, ()> {
        if case == Case::RecoveryPending { return self.pending.as_mut().ok_or(())?.dom(step, value); }
        let only_ready = || value == &json!({"state":"ready"});
        let next = match step {
            Step::Navigate if only_ready() => if case == Case::RecoveryEmpty { Step::Prepare } else if case.signed() { Step::SignedMode } else { Step::ReadVersion },
            Step::SignedMode if case.signed() && only_ready() => Step::ReadVersion,
            Step::ReadVersion if only_ready() => Step::VersionRead,
            Step::VersionRead if self.version.is_some() && *value == json!({"state":"ready",
                "version":"Saved version 1.2.3 · build 7 · source version.properties.","reviewAvailable":true}) => Step::Prepare,
            Step::Prepare if only_ready() => Step::Review,
            Step::Review if self.prepare_returned && self.prepared.is_some() && *value == json!({"state":"ready",
                "checked":false,"startAvailable":false,"identityVisible":true}) => { self.review_visible = true; Step::Acknowledge },
            Step::Acknowledge if only_ready() => Step::Acknowledged,
            Step::Acknowledged if self.review_visible && *value == json!({"state":"ready","checked":true,"startAvailable":true}) => {
                self.acknowledged = true; if case == Case::VersionStale { Step::MutateVersion } else { Step::Start }
            },
            Step::Start if only_ready() => Step::Running,
            Step::Cancel if case == Case::SignedCancel => {
                if value.as_object().is_none_or(|object| object.len() != 2) || value["state"] != "ready"
                    || self.signed_boundary.is_none() || self.cancel_dom_stage.is_some() { return Err(()); }
                let stage = serde_json::from_value::<wire::Stage>(value["stageAtClick"].clone()).map_err(|_| ())?;
                if matches!(stage, wire::Stage::Accepted | wire::Stage::RecoveringAccount | wire::Stage::RecoveringProject) { return Err(()); }
                self.cancel_dom_stage = Some(stage); Step::Running
            },
            Step::Cancel if case == Case::Cancel && only_ready() => Step::Running,
            Step::Hold if case.holds_finality() && self.held.is_some() && self.reciprocal_blocked && !self.released
                && *value == json!({"state":"ready","publicSuccessHidden":true,"readBlocked":true,"reviewBlocked":true,"refreshBlocked":true}) => {
                    self.held_dom = true; Step::ReleaseHold
                },
            Step::Final => {
                let snapshot = self.terminal.as_ref().ok_or(())?;
                if !terminal_for(case, snapshot) { return Err(()); }
                if case == Case::RecoveryEmpty {
                    if *value != json!({"state":"ready","phase":"terminal",
                        "outcome":["Operation outcome: complete. A complete inspection can still find pending state; it is not completed recovery."],
                        "rows":[{"heading":"Account signing state · idle","sessionVisible":false,"recoveryButton":"Review ordinary account recovery","recoveryBlocked":true},
                            {"heading":"Project build-input state · idle","sessionVisible":false,"recoveryButton":"Review ordinary project recovery","recoveryBlocked":true}],
                        "artifactResultPresent":false}) { return Err(()); }
                    self.recovery_actions_blocked = true; self.final_dom = true; return Ok(None);
                }
                let commands = &snapshot.terminal.activity.archive_activity().ok_or(())?.commands;
                let words = |label: &str, command: &wire::CommandData| match command.outcome {
                    wire::CommandOutcome::Exited => format!("{label}: known exit {}.", command.exit_code.unwrap_or(i32::MIN)),
                    wire::CommandOutcome::NotConfigured => format!("{label}: not configured."),
                    wire::CommandOutcome::NotDispatched => format!("{label}: not dispatched."),
                    wire::CommandOutcome::Unknown => format!("{label}: no usable original outcome."),
                };
                let archive = snapshot.terminal.result.as_ref().map(|result| result.archive.clone());
                let mut lines = vec![words("Xcode version",&commands.xcode_version),words("iOS SDK selection",&commands.ios_sdk),
                    words("Saved preparation",&commands.prepare),words("Archive",&commands.archive)];
                if let Some(export) = &commands.export { lines.push(words("Local IPA export",export)); }
                if *value != json!({"state":"ready","phase":"terminal","outcome":snapshot.terminal.outcome,
                    "commands":lines,
                    "resultPresent":snapshot.terminal.result.is_some(),"archive":archive}) { return Err(()); }
                self.final_dom = true; return Ok(None);
            },
            _ => return Err(()),
        };
        Ok(Some(next))
    }
    pub(super) fn report(&self, case: Case) -> Option<Value> {
        if case == Case::RecoveryPending { return self.pending.as_ref()?.report(); }
        let terminal = self.terminal()?;
        if !self.prepare_requested || !self.prepare_returned || !self.review_visible || !self.acknowledged
            || !self.start_requested || !self.start_returned || self.status_requested != self.status_returned
            || self.cancel_requested != matches!(case, Case::Cancel | Case::SignedCancel) || self.cancel_returned != self.cancel_requested
            || self.released != case.holds_finality() || self.held_dom != self.released || self.reciprocal_blocked != self.released
            || self.held.is_some() != self.released || !terminal_for(case, terminal) { return None; }
        if self.version_mutated != (case == Case::VersionStale) || self.version_requested != (case != Case::RecoveryEmpty)
            || self.version.is_some() != self.version_requested || self.signed_policy.is_some() != case.signed()
            || self.recovery_actions_blocked != (case == Case::RecoveryEmpty)
            || self.signed_boundary.is_some() != (case == Case::SignedCancel) || self.cancel_dom_stage.is_some() != (case == Case::SignedCancel) { return None; }
        let cancel = if case == Case::Cancel {
            Some(json!({"requestedOnce":true,"returned":true,"stageAtClick":"preparing",
                "prepareOutcome":terminal.terminal.activity.archive_activity()?.commands.prepare,"activeCommandKillClaimed":false}))
        } else if case == Case::SignedCancel {
            let (operation, generation) = self.signed_boundary.as_ref()?;
            if *operation != terminal.facts.operation_id || *generation != terminal.facts.owner_generation { return None; }
            Some(json!({"requestedOnce":true,"returned":true,"stageAtClick":self.cancel_dom_stage?,
                "trigger":"original-inputs-bound","boundary":{"stage":"inputs-bound","operationId":operation,
                    "ownerGeneration":generation,"originalTypedFrame":true},"activeCommandKillClaimed":false}))
        } else { None };
        let account = case.signed() || case.recovery();
        let mut report = json!({"protocol":if case == Case::RecoveryEmpty { wire::RECOVERY_PROTOCOL } else if case.signed() { wire::SIGNED_PROTOCOL } else { wire::PROTOCOL },
            "savedVersionObservation":self.version,"context":self.context,
            "prepareRequestedOnce":true,"prepareReturned":true,"reviewVisible":true,"acknowledged":true,
            "startRequestedOnce":true,"startReturned":true,"statusCallsReturned":self.status_returned,
            "staleVersionWriterReturnedAndClosed":self.version_mutated,
            "original":terminal,"finalResultVisible":self.final_dom,
            "prerequisiteOnly":case == Case::ToolchainPrerequisite,
            "cancel":cancel,
            "hold":self.held.as_ref().map(|snapshot| json!({"original":snapshot,"publicSuccessHidden":self.held_dom,
                "conflictingUiBlocked":self.held_dom,"environmentDiagnosticsBlocked":self.reciprocal_blocked,
                "originalReleasedOnce":self.released})),
            "workMs":if account { 120000 } else { 300000 },"hardMs":if account { 250000 } else { 310000 },
            "observationMs":315000,"outerInvocationMs":325000});
        if account { report["cleanupMs"] = json!(240000); }
        if case == Case::RecoveryEmpty { report["recoveryActions"] = json!({"idleRowsVisible":true,"ordinaryButtonsDisabled":true,
            "foreignMutationAttempted":false,"recoveryMutationClaimed":false}); }
        Some(report)
    }
}
