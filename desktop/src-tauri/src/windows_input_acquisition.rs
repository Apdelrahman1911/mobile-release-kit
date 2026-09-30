//! Actual fixed54 caller, not an installer entry point or a qualification flag.
//!
//! The original native books, expected DATA, same-stream manifest and first cause
//! live in one process-lifetime owner before any native method. A poisoned lock
//! leaves that owner retained. There is no replacement owner, background worker,
//! close-on-Drop, ambient destination, process launch, deletion or activation.
//! The isolated compiled-profile consumer is private to the guarded controller.
//! A reviewed protected bootstrap and full installer lifecycle are still required.
#![forbid(unsafe_code)]

use std::sync::{atomic::{AtomicBool, Ordering}, Mutex, OnceLock};
use mrk_windows_installed_native::{AcquisitionByteCounts, AcquisitionCleanupError,
    CloseOutcome, Error as NativeError, InputAcquisition, PUBLICATION_PAYLOADS};
use crate::runtime::windows_version::{Inventory, VersionSpec, TARGET};
use crate::windows_input_acquisition_data::{Cause, FailureLatch, Phase, StreamProof,
    retain_manifest_chunk, INPUTS, RUNTIME_INPUTS, MANIFEST};
pub use crate::windows_input_acquisition_data::{ExpectedInputData, Failure, PolicyError};

static OWNER: OnceLock<Mutex<OriginalAcquisition>> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);

/// A monotonic request, never a claim that a blocked native call is settled.
/// The fixed controller retains and joins its actual watchdog; native work stays
/// on the original calling thread and is never moved to another worker.
pub fn request_stop() { STOP.store(true, Ordering::SeqCst); }
/// Read-only atomic observation for the fixed controller's final gate.
pub(crate) fn stop_is_requested() -> bool { STOP.load(Ordering::SeqCst) }

#[derive(Debug)]
pub enum AcquisitionError {
    Profile(PolicyError),
    NativeConstruction(NativeError),
    AlreadyStarted,
    OwnerUnavailable,
    Failed(AcquisitionFailureReport),
}

/// Copied observation DATA, not custody or proof that retained paths are absent.
/// All original native storage, including Unknown frames, stays in OWNER.
#[derive(Debug)]
pub struct AcquisitionFailureReport {
    pub cause: Failure,
    pub native_first_before_cleanup: Option<NativeError>,
    pub native_first_after_cleanup: Option<NativeError>,
    pub settlement: CloseOutcome,
    pub cleanup_errors: Vec<AcquisitionCleanupError>,
    pub byte_counts: AcquisitionByteCounts,
}
impl AcquisitionError {
    /// Closed labels/counts only. Never format candidate paths or control DATA.
    pub fn diagnostic_line(&self) -> Option<String> {
        let detail = match self {
            Self::Profile(error) => format!("phase=profile;class={};finality=unobserved", error.label()),
            Self::NativeConstruction(error) => format!("phase=construction;class={};finality=unobserved", native_cause(*error).label()),
            Self::AlreadyStarted => "phase=already-started;class=unobserved;finality=unobserved".to_owned(),
            Self::OwnerUnavailable => "phase=owner-unavailable;class=unobserved;finality=unobserved".to_owned(),
            Self::Failed(report) => {
                let ordinal = report.cause.ordinal.map_or_else(|| "none".to_owned(), |n| n.to_string());
                let counts = report.byte_counts;
                format!("phase={};class={};ordinal={};originalsUnknown={};cleanupErrors={};sourceRead={};confirmedWritten={};readbackRead={};writeCountUnknown={}",
                    report.cause.phase.label(), report.cause.cause.label(), ordinal,
                    report.settlement == CloseOutcome::Unknown, report.cleanup_errors.len(),
                    counts.source_read, counts.confirmed_written, counts.readback_read, counts.write_count_unknown)
            },
        };
        let line = format!("MRK_WINDOWS_INPUT_ACQUISITION_FAILURE_V1={detail}\n");
        if line.len() <= 512 { Some(line) } else { None }
    }
}

fn native_cause(error: NativeError) -> Cause {
    match error {
        NativeError::Unavailable => Cause::Unavailable, NativeError::Unsafe => Cause::Unsafe,
        NativeError::Bounds => Cause::Bounds, NativeError::State => Cause::State, NativeError::Unknown => Cause::Unknown,
    }
}

struct OriginalAcquisition {
    native: InputAcquisition,
    expected: ExpectedInputData,
    manifest: Vec<u8>,
    failure: FailureLatch,
    #[cfg(feature = "windows-installer-profile")]
    activation_returned: Option<Result<(), NativeError>>,
}

// Private syntax only: the expression cannot run before the STOP/first-cause
// check. Its actual returned error is retained before observing post-step STOP.
macro_rules! step {
    ($owner:ident, $phase:ident, $ordinal:expr, $expression:expr) => {{
        let phase = Phase::$phase; let ordinal = $ordinal;
        $owner.before(phase, ordinal)?;
        let returned: Result<_, Cause> = $expression;
        $owner.after(phase, ordinal, returned)?
    }};
}

impl OriginalAcquisition {
    fn before(&mut self, phase: Phase, ordinal: Option<usize>) -> Result<(), Failure> {
        self.after(phase, ordinal, Ok(()))
    }
    fn after<T>(&mut self, phase: Phase, ordinal: Option<usize>, returned: Result<T, Cause>) -> Result<T, Failure> {
        self.failure.after(phase, ordinal, returned, STOP.load(Ordering::SeqCst))
    }
    fn source_chunk(&mut self, stream: &mut StreamProof, index: usize, bytes: &[u8]) -> Result<(), PolicyError> {
        stream.observe(bytes)?;
        if index == MANIFEST { retain_manifest_chunk(&mut self.manifest, bytes)?; }
        Ok(())
    }
    fn decode_original_manifest(&self, spec: &VersionSpec) -> Result<(), PolicyError> {
        self.expected.bind_compiled(spec.manifest_sha256())?;
        if spec.components() != ["Mobile Release Kit", "versions", TARGET, spec.manifest_sha256()] {
            return Err(PolicyError::Binding);
        }
        // Hash-before-JSON, Q/core/target/schema/supplier/serialized inventory
        // validation remains in the existing core; no second JSON validator.
        let inventory = spec.decode(&self.manifest).map_err(|_| PolicyError::Manifest)?;
        runtime_roster(&self.expected, &inventory, self.manifest.len() as u64, spec.manifest_sha256())
    }
    fn finality(&mut self) -> Result<(), Failure> {
        step!(self, Finality, None, if self.native.inputs_retained_and_settled() { Ok(()) }
            else { Err(Cause::Policy(PolicyError::Finality)) });
        Ok(())
    }
    fn acquire(&mut self, spec: &VersionSpec) -> Result<(), Failure> {
        let controls = step!(self, Admit, None, self.native.admit_once().map_err(native_cause));
        for (control, original) in controls.iter().enumerate() {
            step!(self, Controls, Some(INPUTS - 2 + control), self.expected.verify_control(control, original).map_err(Cause::Policy));
        }
        // Literal true occurs only after BOTH actual original control proofs.
        step!(self, Create, None, self.native.create_once(true).map_err(native_cause));
        for index in 0..INPUTS {
            let ordinal = Some(index);
            step!(self, StartCopy, ordinal, self.native.start_copy(index).map_err(native_cause));
            let mut source = step!(self, SourceHash, ordinal, self.expected.stream(index).map_err(Cause::Policy));
            loop {
                let bytes = step!(self, SourceNext, ordinal, self.native.copy_next().map_err(native_cause));
                #[cfg(all(test, feature = "windows-installer-protected-fixture"))]
                fixture_after_copy_return(index, bytes.len());
                step!(self, SourceHash, ordinal, self.source_chunk(&mut source, index, &bytes).map_err(Cause::Policy));
                if bytes.is_empty() { break; } // actual native EOF, never guessed from length
            }
            step!(self, SourceVerify, ordinal, source.verify().map_err(Cause::Policy));
            if index == MANIFEST {
                step!(self, Decode, ordinal, self.decode_original_manifest(spec).map_err(Cause::Policy));
            }
            // Hash acceptance cannot bypass the native original flush/once-close.
            step!(self, FinishCopy, ordinal, self.native.finish_copy(true).map_err(native_cause));
            let mut readback = step!(self, ReadbackHash, ordinal, self.expected.stream(index).map_err(Cause::Policy));
            loop {
                let bytes = step!(self, ReadbackNext, ordinal, self.native.readback_next().map_err(native_cause));
                step!(self, ReadbackHash, ordinal, readback.observe(&bytes).map_err(Cause::Policy));
                if bytes.is_empty() { break; }
            }
            step!(self, ReadbackVerify, ordinal, readback.verify().map_err(Cause::Policy));
            step!(self, FinishReadback, ordinal, self.native.finish_readback(true).map_err(native_cause));
        }
        step!(self, Finish, None, self.native.finish_once().map_err(native_cause));
        self.finality()
    }
}

fn runtime_roster(expected: &ExpectedInputData, inventory: &Inventory, manifest_size: u64, compiled: &str)
    -> Result<(), PolicyError> {
    expected.bind_compiled(compiled)?;
    // Reuse the existing exact directory/file closure. Native literal47 remains
    // the sole roster; manifest.json is NOT an entry in manifest.files.
    inventory.passive_loader_inventory().map_err(|_| PolicyError::Manifest)?;
    if PUBLICATION_PAYLOADS.len() != RUNTIME_INPUTS || PUBLICATION_PAYLOADS[MANIFEST] != "manifest.json"
        || inventory.manifest.files.len().checked_add(1) != Some(RUNTIME_INPUTS)
        || !expected.matches(MANIFEST, manifest_size, compiled)
        || inventory.payload_bytes.checked_add(manifest_size) != Some(expected.runtime_bytes()) {
        return Err(PolicyError::Manifest);
    }
    for (index, path) in PUBLICATION_PAYLOADS.iter().enumerate() {
        if index == MANIFEST { continue; }
        let row = inventory.file(path).ok_or(PolicyError::Manifest)?;
        if !expected.matches(index, row.size, &row.sha256) { return Err(PolicyError::Binding); }
    }
    Ok(())
}

/// No CLI/UI route exists. The future fixed, admitted bridge supplies its embedded
/// DATA profile and a protected source candidate; NativeBook must still admit the
/// actual originals. Neither argument grants destination or execution authority.
/// Ok means ONLY retained, verified input acquisition, never installer success.
pub(crate) fn acquire_inputs_once(source_candidate: &str, expected: ExpectedInputData) -> Result<(), AcquisitionError> {
    let spec = VersionSpec::compiled().map_err(|_| AcquisitionError::Profile(PolicyError::Binding))?;
    expected.bind_compiled(spec.manifest_sha256()).map_err(AcquisitionError::Profile)?;
    let image = expected.image().map_err(AcquisitionError::Profile)?;
    let native = InputAcquisition::new(source_candidate, expected.manifest(), expected.helper(), image, expected.sizes())
        .map_err(AcquisitionError::NativeConstruction)?;
    OWNER.set(Mutex::new(OriginalAcquisition { native, expected, manifest: Vec::new(), failure: FailureLatch::default(),
        #[cfg(feature = "windows-installer-profile")]
        activation_returned: None,
    }))
        .map_err(|_| AcquisitionError::AlreadyStarted)?;
    // Constructors above have no native effects. A rejected duplicate cannot
    // replace/settle the original. Lock poisoning leaves all original storage.
    let mut original = OWNER.get().ok_or(AcquisitionError::OwnerUnavailable)?
        .lock().map_err(|_| AcquisitionError::OwnerUnavailable)?;
    // Keep BOTH actual deadline-sensitive finality checks and short-circuit the
    // first error. The final successful STOP load is acquisition's linearization
    // point; a later request cannot make this a successful installer operation.
    let outcome = original.acquire(&spec).and_then(|()| original.finality());
    let first = match outcome { Ok(()) => return Ok(()), Err(first) => first };
    let native_first_before_cleanup = original.native.first_failure();
    // First cause already lives in the original latch. Cleanup still runs on
    // STOP and never substitutes a new owner, retries a close or deletes inputs.
    let settlement = original.native.fail_and_settle_once();
    let report = AcquisitionFailureReport {
        cause: first, native_first_before_cleanup,
        native_first_after_cleanup: original.native.first_failure(), settlement,
        cleanup_errors: original.native.cleanup_errors().to_vec(), byte_counts: original.native.byte_counts(),
    };
    Err(AcquisitionError::Failed(report))
}

/// Construction-only actual acquisition loan. The caller registers Publication
/// only AFTER this function returns and releases the acquisition lock. Any later
/// joint loan uses Publication -> Acquisition, never the watchdog custody mutex.
/// This selects neither activation nor prerequisite success.
#[cfg(feature = "windows-installer-profile")]
pub(crate) fn publication_for_installer(
    guard: &crate::windows_installer_controller::ActiveInstallerGuard<'_>,
    spec: &VersionSpec,
) -> Result<mrk_windows_installed_native::Publication, crate::runtime_publication_windows::PublicationError> {
    use crate::runtime_publication_windows::PublicationError;
    guard.require_acquired_inputs().map_err(|_| PublicationError::InstallerGuard)?;
    let original = OWNER.get().ok_or(PublicationError::OwnerUnavailable)?
        .lock().map_err(|_| PublicationError::OwnerUnavailable)?;
    guard.check().map_err(|_| PublicationError::InstallerGuard)?;
    original.expected.bind_compiled(spec.manifest_sha256()).map_err(|_| PublicationError::Profile)?;
    // Structural closure belongs to the actual native original. Its old
    // deadline-sensitive success bool is NOT resampled as current evidence.
    let returned = mrk_windows_installed_native::Publication::for_installer(&original.native)
        .map_err(|_| PublicationError::Profile);
    guard.after_return(returned, PublicationError::InstallerGuard)
}

/// Inert native construction from this ACTUAL retained acquisition/compiled
/// row49. The acquisition loan ends before the prerequisite owner is registered.
#[cfg(feature = "windows-installer-profile")]
pub(crate) fn for_installer_prerequisite(
    guard: &crate::windows_installer_controller::ActiveInstallerGuard<'_>,
) -> Result<mrk_windows_installed_native::OfflineWebView2Owner, crate::windows_offline_webview2::OfflineWebView2Error> {
    use crate::windows_offline_webview2::OfflineWebView2Error as Error;
    guard.require_acquired_inputs().map_err(|_| Error::InstallerGuard)?;
    let original = OWNER.get().ok_or(Error::AcquisitionUnavailable)?.try_lock()
        .map_err(|_| Error::AcquisitionUnavailable)?;
    guard.check().map_err(|_| Error::InstallerGuard)?;
    let spec = VersionSpec::compiled().map_err(|_| Error::AcquisitionUnavailable)?;
    original.expected.bind_compiled(spec.manifest_sha256()).map_err(|_| Error::AcquisitionUnavailable)?;
    let hash = original.expected.offline_prerequisite_sha256().map_err(|_| Error::AcquisitionUnavailable)?;
    let returned = mrk_windows_installed_native::OfflineWebView2Owner::for_acquisition(&original.native, hash)
        .map_err(Error::NativeConstruction);
    guard.after_return(returned, Error::InstallerGuard)
}

/// Concrete prerequisite -> acquisition loan. The safe prerequisite owner MUST
/// retain this direct native Result before any after-check, cleanup or mapping.
#[cfg(feature = "windows-installer-profile")]
pub(crate) fn run_installer_prerequisite_once(
    prerequisite: &mut mrk_windows_installed_native::OfflineWebView2Owner,
    guard: &crate::windows_installer_controller::ActiveInstallerGuard<'_>,
) -> Result<(), NativeError> {
    guard.require_acquired_inputs().map_err(|_| NativeError::State)?;
    let original = OWNER.get().ok_or(NativeError::State)?.try_lock().map_err(|_| NativeError::State)?;
    guard.check().map_err(|_| NativeError::State)?;
    prerequisite.prepare_once(&original.native, guard)
}

/// Fixed read-only qualification -> acquisition loan. No callback executor or
/// fallback to auto-install. Native result is returned directly so the SAME
/// prerequisite original retains it before another guard sample or cleanup.
#[cfg(all(test, feature = "windows-installer-profile"))]
pub(crate) fn run_existing_installer_prerequisite_once(
    prerequisite: &mut mrk_windows_installed_native::OfflineWebView2Owner,
    guard: &crate::windows_installer_controller::ActiveInstallerGuard<'_>,
) -> Result<(), NativeError> {
    guard.require_acquired_inputs().map_err(|_| NativeError::State)?;
    let original = OWNER.get().ok_or(NativeError::State)?.try_lock().map_err(|_| NativeError::State)?;
    guard.check().map_err(|_| NativeError::State)?;
    prerequisite.prepare_existing_once(&original.native, guard)
}

/// The fixed compiled input arm used by the future admitted installer bridge.
/// The packaging owner must retain/bind these actual profile bytes and the full
/// compiler environment. Compile strings alone are not supplier authentication.
/// No runtime profile/hash/destination override is accepted. This calls the REAL
/// acquisition owner; its STOP, original books, cleanup and finality are unchanged.
/// The public fixed route is windows_installer_controller::run_embedded_acquisition_once.
/// This crate-private arm cannot bypass that route from a future bridge binary.
/// Ok is input acquisition only, never installation.
#[cfg(feature = "windows-installer-profile")]
pub(crate) fn acquire_embedded_inputs_once(source_candidate: &str) -> Result<(), AcquisitionError> {
    use crate::windows_input_acquisition_data::{decode_profile, ProfileBindings};
    let expected = decode_profile(env!("MRK_WINDOWS_INSTALLER_PROFILE_JSON").as_bytes(), &ProfileBindings {
        profile_sha256: env!("MRK_WINDOWS_INSTALLER_PROFILE_SHA256"),
        source_commit: env!("MRK_WINDOWS_INSTALLER_SOURCE_COMMIT"),
        target: crate::runtime::COMPILED_TARGET,
        core_version: crate::runtime::CORE_VERSION,
        manifest_sha256: env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        protocol_sha256: env!("MRK_BUNDLED_PROTOCOL_SHA256"),
    }).map_err(AcquisitionError::Profile)?;
    acquire_inputs_once(source_candidate, expected)
}

#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
static FIXTURE_STOP_ARMED: AtomicBool = AtomicBool::new(false);
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
static FIXTURE_RETURNED_CHUNK: OnceLock<usize> = OnceLock::new();
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
pub(crate) fn fixture_arm_copy_stop_once() -> Result<(), PolicyError> {
    if FIXTURE_STOP_ARMED.swap(true, Ordering::SeqCst) || FIXTURE_RETURNED_CHUNK.get().is_some() {
        return Err(PolicyError::Binding);
    }
    Ok(())
}
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
fn fixture_after_copy_return(index: usize, bytes: usize) {
    // One fixed actual return boundary. Never fabricate a WriteFile failure or
    // replace its count. STOP is latched before the next SourceHash step begins.
    if index == 0 && bytes != 0 && FIXTURE_STOP_ARMED.load(Ordering::SeqCst)
        && FIXTURE_RETURNED_CHUNK.get().is_none() {
        if FIXTURE_RETURNED_CHUNK.set(bytes).is_err() { std::process::abort(); }
        request_stop();
    }
}
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
pub(crate) fn fixture_returned_copy_bytes() -> Option<usize> { FIXTURE_RETURNED_CHUNK.get().copied() }
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
pub(crate) fn fixture_observation(boundary: &crate::windows_installer_controller::ActiveInstallerGuard<'_>)
    -> Option<mrk_windows_installed_native::installer_fixture_data::InstallerFixtureAcquisitionObservation> {
    boundary.settlement_boundary();
    OWNER.get()?.try_lock().ok().map(|o| o.native.retained_fixture_observation())
}
#[cfg(feature = "windows-installer-profile")]
pub(crate) fn activate_retained_once(runtime: &mrk_windows_installed_native::Publication,
    boundary: &crate::windows_installer_controller::ActiveInstallerGuard<'_>) -> Result<(), NativeError> {
    boundary.require_acquired_inputs().map_err(|_| NativeError::State)?;
    // Publication loan is already retained. Never lock watchdog custody again.
    let prerequisite = crate::windows_offline_webview2::borrow_for_activation(boundary)
        .map_err(|_| NativeError::State)?;
    let mut original = OWNER.get().ok_or(NativeError::State)?.try_lock().map_err(|_| NativeError::State)?;
    if original.activation_returned.is_some() { return Err(NativeError::State); }
    let returned = original.native.activate_retained_shell_once(runtime, prerequisite.native(), boundary);
    original.activation_returned = Some(returned); // FIRST, before later guard/observation
    returned
}
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
pub(crate) fn fixture_activate_once(runtime: &mrk_windows_installed_native::Publication,
    boundary: &crate::windows_installer_controller::ActiveInstallerGuard<'_>) -> Result<(), NativeError> {
    activate_retained_once(runtime, boundary)
}

/// Final named acquisition loan. The caller holds actual Publication then
/// CompletedPrerequisite; all three construction loans end before selection IO.
#[cfg(feature = "windows-installer-selection")]
pub(crate) fn selection_for_installer(runtime: &mrk_windows_installed_native::Publication,
    prerequisite: &mrk_windows_installed_native::OfflineWebView2Owner,
    boundary: &crate::windows_installer_controller::ActiveInstallerGuard<'_>,
    confirmed: mrk_windows_installed_native::SelectionPreview,
    proposed: mrk_windows_installed_native::SelectionImageData)
    -> Result<mrk_windows_installed_native::SelectionOwner, crate::windows_installer_selection::SelectionError> {
    use crate::windows_installer_selection::SelectionError;
    boundary.require_acquired_inputs().map_err(|_| SelectionError::InstallerGuard)?;
    let original = OWNER.get().ok_or(SelectionError::OwnerUnavailable)?.try_lock()
        .map_err(|_| SelectionError::OwnerUnavailable)?;
    if !matches!(original.activation_returned, Some(Ok(())))
        || original.expected.image().map_err(SelectionError::Profile)? != proposed.image
        || original.expected.manifest() != proposed.runtime
        || original.expected.sizes() != proposed.input_sizes
        || original.expected.selection_hashes().map_err(SelectionError::Profile)? != proposed.input_hashes {
        return Err(SelectionError::Profile(PolicyError::Binding));
    }
    let returned = mrk_windows_installed_native::SelectionOwner::for_activated(confirmed, proposed,
        &original.native, prerequisite, runtime).map_err(SelectionError::NativeConstruction);
    boundary.after_return(returned, SelectionError::InstallerGuard)
}
#[cfg(all(test, feature = "windows-installer-protected-fixture"))]
pub(crate) fn acquire_fixture_inputs_once(source_candidate: &str,
    inputs: &mrk_windows_installed_native::installer_fixture_data::InstallerFixtureInputs) -> Result<(), AcquisitionError> {
    use crate::windows_input_acquisition_data::{decode_profile, ProfileBindings};
    let expected = decode_profile(inputs.profile, &ProfileBindings {
        profile_sha256: inputs.image, source_commit: env!("MRK_WINDOWS_INSTALLER_SOURCE_COMMIT"),
        target: crate::runtime::COMPILED_TARGET, core_version: crate::runtime::CORE_VERSION,
        manifest_sha256: env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        protocol_sha256: env!("MRK_BUNDLED_PROTOCOL_SHA256"),
    }).map_err(AcquisitionError::Profile)?;
    for i in 0..INPUTS {
        if !expected.matches(i, inputs.sizes[i], inputs.hashes[i]) {
            return Err(AcquisitionError::Profile(PolicyError::Binding));
        }
    }
    acquire_inputs_once(source_candidate, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use crate::runtime::{Manifest, PayloadFile, CORE_VERSION};

    // Roster-only DATA using the actual native constant. Not a decoded supplier
    // manifest, protected fixture, native owner or synthetic success receipt.
    fn fixture() -> (ExpectedInputData, Inventory) {
        let mut hashes = std::array::from_fn(|_| "a".repeat(64));
        hashes[MANIFEST] = "d".repeat(64); hashes[RUNTIME_INPUTS] = "e".repeat(64);
        let expected = ExpectedInputData::new(&"d".repeat(64), &"e".repeat(64), [1; INPUTS], hashes).unwrap();
        let files: Vec<_> = PUBLICATION_PAYLOADS.iter().enumerate().filter(|(i, _)| *i != MANIFEST)
            .map(|(_, p)| PayloadFile { path: (*p).to_owned(), size: 1, sha256: "a".repeat(64) }).collect();
        let inventory = Inventory { payload_bytes: files.len() as u64, directories: BTreeSet::from(["python".to_owned()]),
            manifest: Manifest { schema_version: 1, protocol: crate::protocol::PROTOCOL, core_version: CORE_VERSION.to_owned(),
                target: TARGET.to_owned(), core_sha256: "a".repeat(64), protocol_sha256: "b".repeat(64),
                inventory_sha256: "c".repeat(64), files } };
        (expected, inventory)
    }
    #[test]
    fn actual_runtime_roster_binds_every_row_and_rejects_extra_loader_inputs() {
        let (expected, mut inventory) = fixture();
        assert!(runtime_roster(&expected, &inventory, 1, &"d".repeat(64)).is_ok());
        inventory.manifest.files[0].sha256 = "f".repeat(64);
        assert_eq!(runtime_roster(&expected, &inventory, 1, &"d".repeat(64)), Err(PolicyError::Binding));
        let (expected, mut inventory) = fixture(); inventory.directories.insert("python/DLLs".to_owned());
        assert_eq!(runtime_roster(&expected, &inventory, 1, &"d".repeat(64)), Err(PolicyError::Manifest));
        let (expected, mut inventory) = fixture(); inventory.manifest.files.pop();
        assert_eq!(runtime_roster(&expected, &inventory, 1, &"d".repeat(64)), Err(PolicyError::Manifest));
    }
    #[test]
    fn row7_is_direct_compile_bound_manifest_data_not_a_declared_payload() {
        let (expected, mut inventory) = fixture();
        assert_eq!(PUBLICATION_PAYLOADS[MANIFEST], "manifest.json");
        assert!(inventory.file("manifest.json").is_none());
        assert_eq!(runtime_roster(&expected, &inventory, 2, &"d".repeat(64)), Err(PolicyError::Manifest));
        assert_eq!(runtime_roster(&expected, &inventory, 1, &"f".repeat(64)), Err(PolicyError::Binding));
        inventory.manifest.files.push(PayloadFile { path: "manifest.json".to_owned(), size: 1, sha256: "d".repeat(64) });
        assert_eq!(runtime_roster(&expected, &inventory, 1, &"d".repeat(64)), Err(PolicyError::Manifest));
    }
}

#[cfg(feature = "windows-installer-selection")]
pub(crate) fn retained_activation_settled_for(returned: &Result<(), NativeError>) -> bool {
    OWNER.get().and_then(|owner| owner.try_lock().ok()).is_some_and(|original|
        original.activation_returned.as_ref() == Some(returned) && original.native.shell_activation_settled())
}
