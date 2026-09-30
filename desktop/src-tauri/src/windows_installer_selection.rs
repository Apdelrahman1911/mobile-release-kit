//! Private typed launch-selection/maintenance integration, not an installer.
//! The same original controller guard protects work and settlement. The native
//! owner and every actual return are retained before later guard observations.
//! Preview and Apply are separate one-shot isolated invocations: no guard is
//! held while the user reads a preview. No desktop command or bridge is enabled.
#![forbid(unsafe_code)]

use std::sync::{Mutex, OnceLock};
use mrk_windows_installed_native::{Error as NativeError, SelectionCleanupError, SelectionImageData,
    SelectionMode, SelectionOwner, SelectionPreview, SelectionProfileInput, SelectionReport};
use crate::windows_input_acquisition_data::{decode_profile, decode_retained_profile,
    ExpectedInputData, PolicyError, ProfileBindings};
use crate::windows_installer_controller::ActiveInstallerGuard;

static OWNER: OnceLock<Mutex<OriginalSelection>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionOutcome { Preview(SelectionPreview), Applied(SelectionReport) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionFailurePhase { Observe, Decode, Bind, Complete, PostReturn, Finality }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionFailureReport {
    pub phase: SelectionFailurePhase,
    pub policy: Option<PolicyError>,
    /// Copies of actual returns already in OWNER. None means not entered.
    pub observe_return: Option<Result<(), NativeError>>,
    pub bind_return: Option<Result<(), NativeError>>,
    pub complete_return: Option<Result<(), NativeError>>,
    pub native_first_before_cleanup: Option<NativeError>,
    pub native_first_after_cleanup: Option<NativeError>,
    pub observation: SelectionReport,
    pub cleanup_errors: Vec<SelectionCleanupError>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionError {
    Profile(PolicyError), NativeConstruction(NativeError), InstallerGuard,
    AlreadyStarted, OwnerUnavailable, Failed(SelectionFailureReport),
}
impl SelectionError {
    pub(crate) fn native_settled(&self) -> bool {
        match self {
            Self::Profile(_) | Self::NativeConstruction(_) | Self::InstallerGuard => true,
            Self::AlreadyStarted | Self::OwnerUnavailable => false,
            Self::Failed(report) => report.observation.native_closed,
        }
    }
}
struct OriginalSelection {
    native: SelectionOwner,
    observed: Option<Result<Vec<SelectionProfileInput>, NativeError>>,
    bound: Option<Result<SelectionPreview, NativeError>>,
    completed: Option<Result<SelectionOutcome, NativeError>>,
    reported: Option<Result<SelectionOutcome, SelectionError>>,
}
impl OriginalSelection {
    fn new(native: SelectionOwner) -> Self {
        Self { native, observed: None, bound: None, completed: None, reported: None }
    }
    fn fail(&mut self, boundary: &ActiveInstallerGuard<'_>, phase: SelectionFailurePhase,
        policy: Option<PolicyError>) -> SelectionError {
        let before = self.native.first_failure();
        // Cooperative STOP does not skip required original settlement. Unknown
        // frames remain retained; no new write/record is produced by cleanup.
        boundary.settlement_boundary();
        self.native.settle_once(boundary);
        SelectionError::Failed(SelectionFailureReport {
            phase, policy,
            observe_return: self.observed.as_ref().map(|r| r.as_ref().map(|_| ()).map_err(|e| *e)),
            bind_return: self.bound.as_ref().map(|r| r.as_ref().map(|_| ()).map_err(|e| *e)),
            complete_return: self.completed.as_ref().map(|r| r.as_ref().map(|_| ()).map_err(|e| *e)),
            native_first_before_cleanup: before, native_first_after_cleanup: self.native.first_failure(),
            observation: self.native.report(), cleanup_errors: self.native.cleanup_errors(),
        })
    }
    fn run(&mut self, boundary: &ActiveInstallerGuard<'_>, apply: bool)
        -> Result<SelectionOutcome, SelectionError> {
        if self.observed.is_some() || self.bound.is_some() || self.completed.is_some() || self.reported.is_some() {
            return Err(self.fail(boundary, SelectionFailurePhase::Finality, None));
        }
        // Retain native return FIRST. A later STOP never replaces that result.
        let returned = self.native.observe_once(boundary);
        self.observed = Some(returned);
        let profiles = match self.observed.as_ref() {
            Some(Ok(values)) => values.clone(),
            _ => return Err(self.fail(boundary, SelectionFailurePhase::Observe, None)),
        };
        if boundary.check().is_err() {
            return Err(self.fail(boundary, SelectionFailurePhase::PostReturn, None));
        }
        let mut decoded = Vec::with_capacity(profiles.len());
        for original in profiles {
            let returned = decode_retained_profile(&original.bytes, &original.image)
                .and_then(|data| image_data(data.inputs, original.bytes, data.core_version));
            match returned {
                Ok(value) => decoded.push(value),
                Err(error) => return Err(self.fail(boundary, SelectionFailurePhase::Decode, Some(error))),
            }
        }
        if boundary.check().is_err() {
            return Err(self.fail(boundary, SelectionFailurePhase::PostReturn, None));
        }
        // Native owner compares these exact bytes/hash/image against the held
        // protected originals. Decoded DATA cannot authorize a different image.
        let returned = self.native.bind_profiles_once(boundary, &decoded);
        self.bound = Some(returned);
        if !matches!(self.bound, Some(Ok(_))) {
            return Err(self.fail(boundary, SelectionFailurePhase::Bind, None));
        }
        if boundary.check().is_err() {
            return Err(self.fail(boundary, SelectionFailurePhase::PostReturn, None));
        }
        let returned = if apply {
            self.native.apply_once(boundary).map(SelectionOutcome::Applied)
        } else {
            self.native.finish_preview_once(boundary).map(SelectionOutcome::Preview)
        };
        self.completed = Some(returned); // before any post-return/finality query
        let value = match self.completed.as_ref() {
            Some(Ok(value)) => value.clone(),
            _ => return Err(self.fail(boundary, SelectionFailurePhase::Complete, None)),
        };
        if boundary.check().is_err() {
            return Err(self.fail(boundary, SelectionFailurePhase::PostReturn, None));
        }
        if !self.native.native_closed() || !self.native.cleanup_errors().is_empty() {
            return Err(self.fail(boundary, SelectionFailurePhase::Finality, None));
        }
        Ok(value)
    }
}
fn image_data(inputs: ExpectedInputData, profile: Vec<u8>, core_version: String)
    -> Result<SelectionImageData, PolicyError> {
    let data = SelectionImageData {
        image: inputs.image()?.to_owned(), runtime: inputs.manifest().to_owned(),
        core_version, profile, input_hashes: inputs.selection_hashes()?,
        input_sizes: inputs.sizes(), helper: inputs.helper().to_owned(),
    };
    if data.shape_valid() { Ok(data) } else { Err(PolicyError::Bounds) }
}
fn compiled_image() -> Result<SelectionImageData, SelectionError> {
    let raw = env!("MRK_WINDOWS_INSTALLER_PROFILE_JSON").as_bytes();
    let data = decode_profile(raw, &ProfileBindings {
        profile_sha256: env!("MRK_WINDOWS_INSTALLER_PROFILE_SHA256"),
        source_commit: env!("MRK_WINDOWS_INSTALLER_SOURCE_COMMIT"),
        target: crate::runtime::COMPILED_TARGET, core_version: crate::runtime::CORE_VERSION,
        manifest_sha256: env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        protocol_sha256: env!("MRK_BUNDLED_PROTOCOL_SHA256"),
    }).map_err(SelectionError::Profile)?;
    image_data(data, raw.to_vec(), crate::runtime::CORE_VERSION.to_owned()).map_err(SelectionError::Profile)
}
fn run_original(boundary: &ActiveInstallerGuard<'_>, native: SelectionOwner, apply: bool)
    -> Result<SelectionOutcome, SelectionError> {
    // No native method has run in a constructor. All originals are registered
    // before observe_once; poisoned/unavailable OWNER is never replaced.
    OWNER.set(Mutex::new(OriginalSelection::new(native))).map_err(|_| SelectionError::AlreadyStarted)?;
    let mut original = OWNER.get().ok_or(SelectionError::OwnerUnavailable)?.try_lock()
        .map_err(|_| SelectionError::OwnerUnavailable)?;
    let returned = original.run(boundary, apply);
    original.reported = Some(returned.clone());
    returned
}
pub(crate) fn preview_with_original_guard(boundary: &ActiveInstallerGuard<'_>,
    mode: SelectionMode, recovery: Option<String>) -> Result<SelectionOutcome, SelectionError> {
    let returned = (|| {
        boundary.check().map_err(|_| SelectionError::InstallerGuard)?;
        let native = SelectionOwner::for_preview(mode, compiled_image()?, recovery)
            .map_err(SelectionError::NativeConstruction)?;
        run_original(boundary, native, false)
    })();
    boundary.retain_selection_return(returned)
}
pub(crate) fn maintain_with_original_guard(boundary: &ActiveInstallerGuard<'_>,
    confirmed: SelectionPreview, recovery: Option<String>) -> Result<SelectionOutcome, SelectionError> {
    let returned = (|| {
        boundary.check().map_err(|_| SelectionError::InstallerGuard)?;
        let native = SelectionOwner::for_maintenance(confirmed, compiled_image()?, recovery)
            .map_err(SelectionError::NativeConstruction)?;
        run_original(boundary, native, true)
    })();
    boundary.retain_selection_return(returned)
}
/// Dormant full-installer integration point. Construction must borrow ACTUAL
/// Publication -> Prerequisite -> Acquisition and end those loans before effects.
/// It cannot be reached by the completed acquisition-only entry or a saved flag.
pub(crate) fn select_activated_with_original_guard(boundary: &ActiveInstallerGuard<'_>,
    confirmed: SelectionPreview) -> Result<SelectionOutcome, SelectionError> {
    let returned = (|| {
        boundary.require_acquired_inputs().map_err(|_| SelectionError::InstallerGuard)?;
        boundary.require_publication_return().map_err(|_| SelectionError::InstallerGuard)?;
        let data = compiled_image()?;
        let native = crate::runtime_publication_windows::selection_for_installer(boundary, confirmed, data)?;
        run_original(boundary, native, true)
    })();
    boundary.retain_selection_return(returned)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Returned DATA regression, not native qualification. Post-return STOP must
    // not turn a successful native mutation into an invented native Err.
    #[test]
    fn post_return_failure_keeps_native_success_and_exact_partial_observations() {
        let mut report = SelectionReport::new(SelectionMode::RemoveSelection);
        report.old_move_entered = true; report.old_move_native = Some((1, 0));
        report.native_closed = true; report.completely_closed_phase_mask = 1 << 1;
        let error = SelectionError::Failed(SelectionFailureReport {
            phase: SelectionFailurePhase::PostReturn, policy: None,
            observe_return: Some(Ok(())), bind_return: Some(Ok(())), complete_return: Some(Ok(())),
            native_first_before_cleanup: None, native_first_after_cleanup: None,
            observation: report, cleanup_errors: Vec::new(),
        });
        assert!(error.native_settled());
        let SelectionError::Failed(value) = error else { panic!("wrong DATA variant") };
        assert_eq!(value.complete_return, Some(Ok(())));
        assert_eq!(value.observation.old_move_native, Some((1, 0)));
        assert_eq!(value.observation.completely_closed_phase_mask, 1 << 1);
        assert!(value.observation.controller_finality_required);
        assert!(!SelectionError::OwnerUnavailable.native_settled());
    }
}

/// The controller queries the ACTUAL registered owner after its original loan
/// has ended. A copied native_closed field can never supply this gate.
pub(crate) fn original_settled_for(returned: &Result<SelectionOutcome, SelectionError>) -> bool {
    match OWNER.get() {
        Some(owner) => owner.try_lock().ok().is_some_and(|original|
            original.reported.as_ref() == Some(returned) && original.native.native_closed()),
        None => matches!(returned, Err(SelectionError::Profile(_) | SelectionError::NativeConstruction(_)
            | SelectionError::InstallerGuard)),
    }
}


#[cfg(all(test, feature = "windows-installer-selection-fixture"))]
fn fixture_image(case: mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixtureCase)
    -> Result<SelectionImageData, SelectionError> {
    use mrk_windows_installed_native::installer_fixture_data::installer_fixture_inputs;
    let input = installer_fixture_inputs(case.input_case()).map_err(SelectionError::NativeConstruction)?;
    if input.source_commit != env!("MRK_WINDOWS_INSTALLER_SOURCE_COMMIT")
        || input.core_version != crate::runtime::CORE_VERSION {
        return Err(SelectionError::Profile(PolicyError::Binding));
    }
    let decoded = decode_profile(input.profile, &ProfileBindings {
        profile_sha256: input.image, source_commit: env!("MRK_WINDOWS_INSTALLER_SOURCE_COMMIT"),
        target: crate::runtime::COMPILED_TARGET, core_version: crate::runtime::CORE_VERSION,
        manifest_sha256: env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        protocol_sha256: env!("MRK_BUNDLED_PROTOCOL_SHA256"),
    }).map_err(SelectionError::Profile)?;
    for ordinal in 0..54 {
        if !decoded.matches(ordinal, input.sizes[ordinal], input.hashes[ordinal]) {
            return Err(SelectionError::Profile(PolicyError::Binding));
        }
    }
    image_data(decoded, input.profile.to_vec(), input.core_version.to_owned()).map_err(SelectionError::Profile)
}
#[cfg(all(test, feature = "windows-installer-selection-fixture"))]
pub(crate) fn fixture_with_original_guard(boundary: &ActiveInstallerGuard<'_>,
    case: mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixtureCase,
    confirmed: Option<SelectionPreview>, recovery: Option<String>) -> Result<SelectionOutcome, SelectionError> {
    let returned = (|| {
        boundary.check().map_err(|_| SelectionError::InstallerGuard)?;
        let image = fixture_image(case)?;
        let mut native = if case.preview() {
            if confirmed.is_some() { return Err(SelectionError::InstallerGuard); }
            SelectionOwner::for_preview(case.mode(), image, recovery).map_err(SelectionError::NativeConstruction)?
        } else if case.acquires() {
            boundary.require_acquired_inputs().map_err(|_| SelectionError::InstallerGuard)?;
            boundary.require_publication_return().map_err(|_| SelectionError::InstallerGuard)?;
            if recovery.is_some() { return Err(SelectionError::InstallerGuard); }
            crate::runtime_publication_windows::selection_for_installer(boundary,
                confirmed.ok_or(SelectionError::InstallerGuard)?, image)?
        } else {
            SelectionOwner::for_maintenance(confirmed.ok_or(SelectionError::InstallerGuard)?, image, recovery)
                .map_err(SelectionError::NativeConstruction)?
        };
        // DATA-only fixture selection before native work; the original itself
        // is registered by run_original before any OS effect/observation.
        native.fixture_arm_once(case).map_err(SelectionError::NativeConstruction)?;
        run_original(boundary, native, !case.preview())
    })();
    boundary.retain_selection_return(returned)
}
#[cfg(all(test, feature = "windows-installer-selection-fixture"))]
pub(crate) fn fixture_observation()
    -> Option<mrk_windows_installed_native::installer_selection_fixture_data::SelectionFixtureObservation> {
    let original = OWNER.get()?.try_lock().ok()?;
    original.reported.as_ref()?;
    Some(original.native.fixture_observation())
}
