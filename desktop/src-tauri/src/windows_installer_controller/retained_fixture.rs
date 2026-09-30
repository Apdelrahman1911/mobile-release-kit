//! Five fixed, separate process libtests. No replacement controller or native
//! owner; the parent module supplies its actual original setup/guard/join path.
//! The existing outer process owner MUST bind compiler inputs, exact argv,
//! original wait/exit and output. Eligibility strings are not that authority.
use super::*;
use crate::runtime_publication_windows as publication;
use crate::windows_input_acquisition_data::{Cause, Phase, PolicyError};
use crate::windows_offline_webview2 as prerequisite;
use mrk_windows_installed_native::{InstallerRuntimeMode, OfflineWebView2Mode};
use mrk_windows_installed_native::installer_fixture_data::{
    installer_fixture_eligibility, installer_fixture_inputs, InstallerFixtureCase as Case,
    InstallerFixtureAcquisitionObservation as AcquisitionObservation,
    InstallerFixturePublicationObservation as PublicationObservation,
};

#[derive(Debug)]
pub(super) struct CaseProof {
    acquisition: AcquisitionObservation,
    runtime: &'static str,
    prerequisite: &'static str,
}
fn require(value: bool, label: &'static str) -> Result<(), &'static str> {
    if value { Ok(()) } else { Err(label) }
}
pub(super) fn acquire(case: Case, candidate: &str) -> Result<(), AcquisitionError> {
    let inputs = installer_fixture_inputs(case)
        .map_err(|_| AcquisitionError::Profile(PolicyError::Binding))?;
    if case == Case::StopCopy {
        acquisition::fixture_arm_copy_stop_once().map_err(AcquisitionError::Profile)?;
    }
    if case == Case::Fresh {
        if inputs.profile != env!("MRK_WINDOWS_INSTALLER_PROFILE_JSON").as_bytes()
            || inputs.image != env!("MRK_WINDOWS_INSTALLER_PROFILE_SHA256") {
            return Err(AcquisitionError::Profile(PolicyError::Binding));
        }
        acquisition::acquire_embedded_inputs_once(candidate)
    } else { acquisition::acquire_fixture_inputs_once(candidate, &inputs) }
}
fn acquired(boundary: &ActiveInstallerGuard<'_>) -> Result<AcquisitionObservation, &'static str> {
    acquisition::fixture_observation(boundary).ok_or("actual-acquisition-owner-unavailable")
}
fn readonly(observation: PublicationObservation) -> Result<(), &'static str> {
    require(observation.mode == Some(InstallerRuntimeMode::ReuseExisting)
        && observation.originals_settled && observation.creations == 0 && !observation.target_intent
        && observation.directory_controls == 0 && observation.copied_rows == 0
        && observation.sealed_rows == 0 && !observation.has_transfer && !observation.exposure_attempted,
        "reuse-has-producing-records")
}
fn prepare_existing(boundary: &ActiveInstallerGuard<'_>) -> Result<(), &'static str> {
    // No fallback. DATA row49 is NEVER a vendor executable in this fixture.
    let result = prerequisite::prepare_existing_for_fixture_once(boundary);
    match result {
        Ok(prepared) => require(prepared.mode() == OfflineWebView2Mode::AlreadyPresent
            && !prepared.retained_support().created && !prepared.retained_support().retained,
            "existing-prerequisite-mode"),
        Err(prerequisite::OfflineWebView2Error::Failed(report)) => {
            if report.settlement != CloseOutcome::Settled {
                boundary.owner.control.abort(ControllerFault::NativeFinalityUnknown);
            }
            Err("genuine-existing-prerequisite-refused")
        },
        Err(prerequisite::OfflineWebView2Error::AlreadyStarted | prerequisite::OfflineWebView2Error::OwnerUnavailable) =>
            boundary.owner.control.abort(ControllerFault::NativeFinalityUnknown),
        Err(_) => Err("existing-prerequisite-admission-refused"),
    }
}
pub(super) fn after_acquisition(case: Case, boundary: &ActiveInstallerGuard<'_>) -> Result<CaseProof, &'static str> {
    after_acquisition_mode(case, boundary, false)
}
#[cfg(feature = "windows-installer-selection-fixture")]
pub(super) fn prepare_selection(case: Case, boundary: &ActiveInstallerGuard<'_>) -> Result<CaseProof, &'static str> {
    require(matches!(case, Case::Fresh | Case::Reuse | Case::WrongCaller | Case::BadManifest),
        "selection-input-case")?;
    after_acquisition_mode(case, boundary, true)
}
fn after_acquisition_mode(case: Case, boundary: &ActiveInstallerGuard<'_>, selection: bool) -> Result<CaseProof, &'static str> {
    let inputs = installer_fixture_inputs(case).map_err(|_| "compile-data-refused")?;
    let observation = acquired(boundary)?;
    require(observation.original_books_settled && !observation.byte_counts.write_count_unknown
        && !observation.activation_started, "acquisition-original-settlement")?;
    if !selection && case == Case::StopCopy {
        let count = acquisition::fixture_returned_copy_bytes().ok_or("no-actual-first-copy-return")? as u64;
        let report = match boundary.owner.returned.get() {
            Some(Err(AcquisitionError::Failed(report))) => report,
            _ => return Err("STOP-did-not-fail-actual-acquisition"),
        };
        require(count > 0 && count <= inputs.sizes[0]
            && report.cause.phase == Phase::SourceHash && report.cause.ordinal == Some(0)
            && report.cause.cause == Cause::Stopped && report.settlement == CloseOutcome::Settled
            && report.cleanup_errors.is_empty() && report.byte_counts == observation.byte_counts
            && observation.controls_read_bytes == inputs.sizes[52] + inputs.sizes[53]
            && observation.byte_counts.source_read == observation.controls_read_bytes + count
            && observation.byte_counts.confirmed_written == count && observation.byte_counts.readback_read == 0
            && observation.complete_rows == 0 && observation.partial_ordinal == Some(0)
            && observation.partial_writer_closed && publication::fixture_owner_absent(),
            "STOP-cause-accounting-or-cleanup")?;
        return Ok(CaseProof { acquisition: observation, runtime: "not-started", prerequisite: "not-started" });
    }
    require(matches!(boundary.owner.returned.get(), Some(Ok(()))), "actual-acquisition-refused")?;
    let total: u64 = inputs.sizes.iter().sum();
    require(observation.complete_rows == 54 && observation.partial_ordinal.is_none()
        && observation.byte_counts.source_read == total && observation.byte_counts.confirmed_written == total
        && observation.byte_counts.readback_read == total, "full54-accounting")?;
    if !selection && case == Case::WrongCaller {
        // The same borrowed actual guard, no moved native owner or new guard.
        // The scoped original is genuinely joined BEFORE watchdog retirement.
        let returned = thread::scope(|scope| {
            let original = thread::Builder::new().stack_size(WATCHDOG_STACK_BYTES)
                .spawn_scoped(scope, || boundary.check())
                .unwrap_or_else(|_| boundary.owner.control.abort(ControllerFault::SpawnUnavailable));
            match original.join() {
                Ok(returned) => returned,
                Err(_) => boundary.owner.control.abort(ControllerFault::ControllerState),
            }
        });
        require(returned == Err(ControllerFault::ControllerState), "wrong-caller-not-refused")?;
        let refused = publication::publish_for_installer(boundary);
        require(refused == Err(PublicationError::InstallerGuard) && publication::fixture_owner_absent()
            && boundary.owner.publication_returned.get().is_none(), "wrong-caller-created-publication-owner")?;
        return Ok(CaseProof { acquisition: observation, runtime: "caller-refused", prerequisite: "not-started" });
    }

    // Do this BEFORE publication can create versions/change MRK's original Facts.
    prepare_existing(boundary)?;
    let published = publication::publish_for_installer(boundary);
    let publication_observation = publication::fixture_observation(boundary).ok_or("actual-publication-owner-unavailable")?;
    if !publication_observation.originals_settled {
        boundary.owner.control.abort(ControllerFault::NativeFinalityUnknown);
    }
    if !selection && case == Case::BadManifest {
        let error = published.err().ok_or("corrupt-own-manifest-was-accepted")?;
        require(publication::fixture_own_manifest_decode_refusal(error)
            && matches!(boundary.owner.publication_returned.get(), Some(Err(actual)) if *actual == error)
            && !publication_observation.reused && !publication_observation.published,
            "failure-not-own-manifest-decode")?;
        readonly(publication_observation)?;
        require(!acquired(boundary)?.activation_started, "failed-reuse-entered-activation")?;
        return Ok(CaseProof { acquisition: observation, runtime: "own-manifest-refused", prerequisite: "already-present" });
    }
    let expected = if case == Case::Fresh { RuntimePrepared::PublishedNew } else { RuntimePrepared::ReusedExisting };
    require(published == Ok(expected) && matches!(boundary.owner.publication_returned.get(), Some(Ok(actual)) if *actual == expected),
        "wrong-actual-runtime-mode")?;
    if case != Case::Fresh {
        readonly(publication_observation)?;
        require(publication_observation.reused && publication_observation.readonly_rows == 47
            && !publication_observation.readonly_current, "readonly-roster-incomplete")?;
    } else {
        require(publication_observation.mode == Some(InstallerRuntimeMode::PublishNew)
            && publication_observation.published && publication_observation.copied_rows == 47
            && publication_observation.sealed_rows == 47 && publication_observation.exposure_attempted,
            "fresh-did-not-publish47")?;
    }
    #[cfg(feature = "windows-installer-selection-fixture")]
    let returned = if selection { publication::activate_retained_for_installer(boundary) }
        else { publication::fixture_activate_once(boundary) };
    #[cfg(not(feature = "windows-installer-selection-fixture"))]
    let returned = publication::fixture_activate_once(boundary);
    // The safe acquisition original retained the actual native Result already.
    let activated = acquired(boundary)?;
    if activated.activation_started && !activated.activation_settled {
        boundary.owner.control.abort(ControllerFault::NativeFinalityUnknown);
    }
    require(returned == Ok(()) && activated.activation_completed && activated.activation_cleanup_errors == 0
        && activated.roles_mask == 0x3f && activated.public_roles_mask == 0x3f
        && activated.controls_mask == activated.transition_mask && !activated.unexpected_control
        && activated.transition_mask == if case == Case::Fresh { 0x3f } else { 0x38 },
        "six-role-activation-incomplete")?;
    boundary.check().map_err(|_| "post-activation-guard")?;
    Ok(CaseProof { acquisition: activated, runtime: if case == Case::Fresh { "published-new" } else { "reused-existing" },
        prerequisite: "already-present" })
}
fn run(case: Case) -> Result<(), &'static str> {
    installer_fixture_eligibility(case).map_err(|_| "fixed-owned-process-route-required")?;
    let inputs = installer_fixture_inputs(case).map_err(|_| "compile-data-refused")?;
    // Untrusted source hint, supplied by the outer owner from the actual native
    // stager's result. It is NEVER destination/location/acquisition authority.
    // The real InputAcquisition independently checks every original, ACL, byte,
    // ancestry, overlap and OS-derived destination. A bad hint can only refuse.
    let candidate = std::env::var("MRK_WINDOWS_RETAINED_FIXTURE_SOURCE").map_err(|_| "source-hint-missing")?;
    require(candidate.rsplit('\\').next() == Some(inputs.source_leaf().as_str())
        && !candidate.contains('/') && !candidate.contains('\0'), "source-hint-shape")?;
    let returned = run_fixed_acquisition_once(&candidate, FixedAcquisitionArm::Fixture(case));
    let owner = OWNER.get().ok_or("actual-controller-missing")?;
    require(owner.original_joined.get().is_some() && owner.watchdog.try_lock().map_err(|_| "watchdog-custody")?.is_none(),
        "original-watchdog-not-joined")?;
    let proof = match owner.fixture_returned.get() {
        Some(Ok(proof)) => proof,
        Some(Err(label)) => return Err(label),
        None => return Err("fixture-path-not-completed"),
    };
    match case {
        Case::Fresh | Case::Reuse => require(returned.is_ok(), "successful-case-controller-refused")?,
        Case::StopCopy => require(matches!(returned, Err(ControllerError::Failed(_)))
            && owner.control.failures().first == Some(ControllerFault::StopRequested), "STOP-controller-result")?,
        Case::WrongCaller => require(matches!(returned, Err(ControllerError::Failed(_)))
            && owner.control.failures().first == Some(ControllerFault::ControllerState), "caller-controller-result")?,
        Case::BadManifest => require(matches!(returned, Err(ControllerError::Failed(_)))
            && owner.control.failures().first == Some(ControllerFault::PublicationFailed), "decode-controller-result")?,
    }
    let observed = proof.acquisition;
    // Closed counts/status only. The outer ORIGINAL owner captures this output,
    // binds its bytes and real exit0, and supplies private source-bound evidence.
    // Printing is not original process finality or production installer success.
    println!("\nMRK_WINDOWS_RETAINED_SHELL_CASE_V1=case={};rows={};sourceRead={};confirmedWritten={};readbackRead={};prerequisite={};runtime={};activation={};roles={};transitions={};originalWatchdogJoined=true;nativeSettled=true",
        case.label(), observed.complete_rows, observed.byte_counts.source_read,
        observed.byte_counts.confirmed_written, observed.byte_counts.readback_read,
        proof.prerequisite, proof.runtime, observed.activation_completed, observed.roles_mask, observed.transition_mask);
    Ok(())
}
#[test]
#[ignore = "real protected fixed54/47 fixture; one exact test per original-owned Windows process"]
fn owned_fresh() -> Result<(), &'static str> { run(Case::Fresh) }
#[test]
#[ignore = "same owned D, distinct real I, original D/IA unchanged; separate process"]
fn owned_reuse() -> Result<(), &'static str> { run(Case::Reuse) }
#[test]
#[ignore = "absorbing STOP after actual first copy return; separate process"]
fn owned_stop_copy() -> Result<(), &'static str> { run(Case::StopCopy) }
#[test]
#[ignore = "same actual guard on scoped joined wrong caller; separate process"]
fn owned_wrong_caller() -> Result<(), &'static str> { run(Case::WrongCaller) }
#[test]
#[ignore = "last namespace user; genuine owned manifest corruption must precede actual reuse"]
fn owned_bad_manifest() -> Result<(), &'static str> { run(Case::BadManifest) }
