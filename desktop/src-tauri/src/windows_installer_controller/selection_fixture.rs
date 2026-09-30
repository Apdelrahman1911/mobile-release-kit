//! Fixed ignored Windows selection cases, each in one original-owned process.
//! This extends the existing controller/outer fixture route, not a harness.
//! The outer owner captures real preview DATA, supplies it to a LATER apply
//! process, verifies namespace postconditions/preserved trees and joins originals.
//! No eligibility string, printed line or preview proves native/CI finality.
use super::*;
use crate::windows_installer_selection as selection;
use mrk_windows_installed_native::{SelectionDisposition, SelectionMode, SelectionPreview};
use mrk_windows_installed_native::installer_selection_data as data;
use mrk_windows_installed_native::installer_selection_fixture_data::{
    selection_fixture_eligibility, selection_accounting_encode, SELECTION_ACCOUNTING_PREFIX,
    SelectionFixtureCase as Case,
    SelectionFixtureObservation as Observation, SelectionFixturePoint as Point,
};
use mrk_windows_installed_native::installer_fixture_data::installer_fixture_inputs;
use serde::{Deserialize, Serialize};

struct Request {
    case: Case,
    confirmed: Option<SelectionPreview>,
    recovery: Option<String>,
}
static REQUEST: OnceLock<Request> = OnceLock::new();
static PREPARATION: OnceLock<Result<retained_fixture::CaseProof, &'static str>> = OnceLock::new();
static STOP_OBSERVED: OnceLock<Point> = OnceLock::new();

fn require(value: bool, why: &'static str) -> Result<(), &'static str> {
    if value { Ok(()) } else { Err(why) }
}

/// Fixture transport only, bounded and closed. Production Apply still reopens
/// originals and compares the complete snapshot. No native authority is decoded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewWire {
    version: u32, mode: String, before_image: Option<String>, after_image: Option<String>,
    runtime: Option<String>, core_version: Option<String>, shortcut_path: String,
    registration_path: String, observation_sha256: String, preserved_paths: Vec<String>,
    retained_image_bytes_observed: Option<u64>, warning: String,
}
impl PreviewWire {
    fn from_preview(preview: &SelectionPreview) -> Self {
        Self { version: 1, mode: preview.mode.name().to_owned(),
            before_image: preview.before_image.clone(), after_image: preview.after_image.clone(),
            runtime: preview.runtime.clone(), core_version: preview.core_version.clone(),
            shortcut_path: preview.shortcut_path.clone(), registration_path: preview.registration_path.to_owned(),
            observation_sha256: preview.observation_sha256.clone(), preserved_paths: preview.preserved_paths.clone(),
            retained_image_bytes_observed: preview.retained_image_bytes_observed, warning: preview.warning.to_owned() }
    }
    fn decode(raw: &str, mode: SelectionMode) -> Result<SelectionPreview, &'static str> {
        require(!raw.is_empty() && raw.len() <= 16 * 1024 && !raw.contains('\0'), "preview-input-bounds")?;
        let value: Self = serde_json::from_str(raw).map_err(|_| "preview-input-schema")?;
        require(value.version == 1 && value.mode == mode.name()
            && value.registration_path == data::REGISTRATION && value.warning == data::RECOVERY_WARNING
            && data::digest(&value.observation_sha256)
            && [&value.before_image, &value.after_image, &value.runtime].iter()
                .all(|v| v.as_ref().is_none_or(|s| data::digest(s)))
            && value.core_version.as_ref().is_none_or(|s| data::version(s))
            && data::native_dos_path(&value.shortcut_path)
            && value.preserved_paths.len() == 4 && value.preserved_paths.iter().all(|s| data::native_dos_path(s)),
            "preview-input-shape")?;
        require(serde_json::to_string(&value).map_err(|_| "preview-canonical-encoding")? == raw,
            "preview-noncanonical-transport")?;
        Ok(SelectionPreview { mode, before_image: value.before_image, after_image: value.after_image,
            runtime: value.runtime, core_version: value.core_version, shortcut_path: value.shortcut_path,
            registration_path: data::REGISTRATION, observation_sha256: value.observation_sha256,
            preserved_paths: value.preserved_paths, retained_image_bytes_observed: value.retained_image_bytes_observed,
            warning: data::RECOVERY_WARNING })
    }
}
fn requested(case: Case) -> Result<&'static Request, &'static str> {
    REQUEST.get().filter(|r| r.case == case).ok_or("one-shot-request-missing-or-changed")
}
pub(super) fn observe_return(boundary: &ActiveInstallerGuard<'_>, point: Point) {
    let Some(request) = REQUEST.get() else { return; };
    if request.case.stop_point() != Some(point) { return; }
    if !std::ptr::eq(boundary.owner, OWNER.get().unwrap_or_else(|| std::process::abort()))
        || STOP_OBSERVED.set(point).is_err() {
        boundary.owner.control.abort(ControllerFault::ControllerState);
    }
    // Same existing production STOP route. The native return was retained
    // before this observation, and no return value/native operation is changed.
    request_stop();
}
pub(super) fn acquire(case: Case, source: &str) -> Result<(), AcquisitionError> {
    if !case.acquires() || requested(case).is_err() {
        return Err(AcquisitionError::Profile(crate::windows_input_acquisition_data::PolicyError::Binding));
    }
    retained_fixture::acquire(case.input_case(), source)
}
pub(super) fn after_acquisition(case: Case, boundary: &ActiveInstallerGuard<'_>) {
    let prepared = if matches!(boundary.owner.returned.get(), Some(Ok(()))) {
        retained_fixture::prepare_selection(case.input_case(), boundary)
    } else { Err("actual-acquisition-refused") };
    if PREPARATION.set(prepared).is_err() {
        boundary.owner.control.abort(ControllerFault::ControllerState);
    }
    if PREPARATION.get().is_none_or(|r| r.is_err()) {
        boundary.owner.control.fail(ControllerFault::ControllerState); return;
    }
    perform(case, boundary);
}
pub(super) fn perform(case: Case, boundary: &ActiveInstallerGuard<'_>) {
    let request = requested(case).unwrap_or_else(|_| boundary.owner.control.abort(ControllerFault::ControllerState));
    let _ = selection::fixture_with_original_guard(boundary, case, request.confirmed.clone(), request.recovery.clone());
}
fn no_selection_effects(observed: &Observation) -> Result<(), &'static str> {
    let report = &observed.report;
    require(!report.old_move_entered && !report.new_move_entered && !report.registry_commit_entered,
        "unexpected-authoritative-selection-effect")
}
fn readonly54(observed: &Observation) -> Result<(), &'static str> {
    require(observed.input_rows_verified == 54 && observed.runtime_rows_verified == 47
        && observed.readonly_originals_closed, "actual-readonly54-runtime47-incomplete")
}
fn verify_case(case: Case, controller: &Result<(), ControllerError>, original: &'static OriginalController,
    observed: &Observation) -> Result<(), &'static str> {
    let report = &observed.report;
    require(report.native_closed && observed.readonly_originals_closed && observed.registry_competitor_closed
        && !report.write_count_unknown && report.output_bytes_confirmed <= report.output_bytes_charged,
        "native-originals-or-output-accounting-unsettled")?;
    let returned = original.selection_returned.get().ok_or("selection-return-not-retained")?;
    if case.preview() && case != Case::RefuseForeignSelector {
        require(controller.is_ok() && matches!(returned, Ok(SelectionOutcome::Preview(_))), "preview-not-completed")?;
        no_selection_effects(observed)?;
        require(report.outputs.is_empty() && report.output_bytes_charged == 0, "preview-produced-output")?;
        if matches!(case.mode(), SelectionMode::RepairSameImage | SelectionMode::RecoverPrevious | SelectionMode::RecoverCurrent) {
            readonly54(observed)?;
        }
        return Ok(());
    }
    match case {
        Case::StopOld | Case::StopNew => {
            require(controller.is_err() && returned.is_err()
                && original.control.failures().first == Some(ControllerFault::StopRequested)
                && STOP_OBSERVED.get().copied() == case.stop_point()
                && report.disposition == SelectionDisposition::Partial
                && report.old_move_entered && report.old_move_native == Some((1, 0))
                && !report.registry_commit_entered && !report.registry_committed,
                "STOP-return-order-or-partial-state")?;
            if case == Case::StopOld {
                require(!report.new_move_entered && report.new_move_native.is_none()
                    && report.completely_closed_phase_mask == 0b0000011
                    && report.completely_closed_records == 2 && report.os_flush_acknowledged_records == 2,
                    "STOP-old-return-produced-later-record-or-effect")?;
            } else {
                require(report.new_move_entered && report.new_move_native == Some((1, 0))
                    && report.completely_closed_phase_mask == 0b0001111
                    && report.completely_closed_records == 4 && report.os_flush_acknowledged_records == 4,
                    "STOP-new-return-produced-later-record-or-effect")?;
            }
            readonly54(observed)?;
        },
        Case::RegistryConflict => {
            require(controller.is_err() && returned.is_err()
                && observed.registry_conflict_staged && observed.registry_conflict_returned
                && report.disposition == SelectionDisposition::Unchanged
                && observed.registry_competitor_output.as_ref().is_some_and(|r|
                    r.output_bytes_charged > 0 && r.output_bytes_confirmed == r.output_bytes_charged),
                "genuine-transacted-registry-conflict-not-observed")?;
            no_selection_effects(observed)?;
            require(report.completely_closed_records == 0, "conflict-reached-selector-intent")?;
        },
        Case::RefuseStaleRepair | Case::RefuseForeignSelector => {
            require(controller.is_err() && returned.is_err()
                && report.disposition == SelectionDisposition::Unchanged
                && report.outputs.is_empty() && report.output_bytes_charged == 0,
                "changed-preview-or-foreign-selector-not-refused-unchanged")?;
            no_selection_effects(observed)?;
        },
        _ => {
            require(controller.is_ok() && matches!(returned, Ok(SelectionOutcome::Applied(_))),
                "apply-not-completed")?;
            require(report.disposition == if case.mode() == SelectionMode::RemoveSelection {
                SelectionDisposition::LaunchEntriesRemoved
            } else { SelectionDisposition::Selected }, "wrong-selection-disposition")?;
            if case == Case::VerifyReuse {
                readonly54(observed)?;
                no_selection_effects(observed)?;
                require(report.outputs.is_empty() && report.output_bytes_charged == 0, "readonly-verify-mutated")?;
            } else {
                require(report.registry_committed && report.registry_native == Some((1, 0))
                    && report.completely_closed_phase_mask & (1 << 5) != 0
                    && report.completely_closed_phase_mask & (1 << 6) != 0,
                    "registry-intent-return-or-closure-missing")?;
                if case.mode() == SelectionMode::RemoveSelection {
                    require(observed.input_rows_verified == 0 && observed.runtime_rows_verified == 0
                        && report.retained_image_bytes_observed.is_none()
                        && !report.new_move_entered, "remove-required-or-mutated-payload")?;
                } else { readonly54(observed)?; }
            }
        },
    }
    Ok(())
}
fn run(case: Case) -> Result<(), &'static str> {
    selection_fixture_eligibility(case).map_err(|_| "fixed-original-owned-process-route-required")?;
    let confirmed = if case.preview() {
        require(std::env::var_os("MRK_WINDOWS_SELECTION_FIXTURE_PREVIEW").is_none(),
            "preview-must-not-consume-confirmation")?; None
    } else {
        let raw = std::env::var("MRK_WINDOWS_SELECTION_FIXTURE_PREVIEW").map_err(|_| "actual-prior-preview-required")?;
        Some(PreviewWire::decode(&raw, case.mode())?)
    };
    let recovery = if case.mode().recovery() {
        let run = std::env::var("MRK_WINDOWS_SELECTION_FIXTURE_RECOVERY").map_err(|_| "owned-recovery-id-required")?;
        require(data::recovery_id(&run), "recovery-id-shape")?; Some(run)
    } else {
        require(std::env::var_os("MRK_WINDOWS_SELECTION_FIXTURE_RECOVERY").is_none(), "unexpected-recovery-id")?; None
    };
    REQUEST.set(Request { case, confirmed, recovery }).map_err(|_| "duplicate-fixture-request")?;
    let returned = if case.acquires() {
        let input = installer_fixture_inputs(case.input_case()).map_err(|_| "compile-bound-input-data")?;
        let candidate = std::env::var("MRK_WINDOWS_RETAINED_FIXTURE_SOURCE").map_err(|_| "source-hint-missing")?;
        require(candidate.rsplit('\\').next() == Some(input.source_leaf().as_str())
            && !candidate.contains('/') && !candidate.contains('\0'), "source-hint-shape")?;
        run_fixed_acquisition_once(&candidate, FixedAcquisitionArm::SelectionFixture(case))
    } else {
        run_fixed_work_once(FixedControllerWork::SelectionFixture(case))
    };
    let original = OWNER.get().ok_or("actual-controller-missing")?;
    require(original.original_joined.get().is_some()
        && original.watchdog.try_lock().map_err(|_| "watchdog-custody")?.is_none(), "original-watchdog-not-joined")?;
    if case.acquires() {
        require(PREPARATION.get().is_some_and(|r| r.is_ok()), "actual-publication-prerequisite-activation-not-prepared")?;
    }
    let observed = selection::fixture_observation().ok_or("actual-selection-owner-unavailable")?;
    verify_case(case, &returned, original, &observed)?;
    let accounting_preview = match original.selection_returned.get() {
        Some(Ok(SelectionOutcome::Preview(preview))) => Some(preview),
        _ => requested(case)?.confirmed.as_ref(),
    };
    let accounting = selection_accounting_encode(case, &observed, accounting_preview)
        .map_err(|_| "actual-accounting-schema-or-bound")?;
    if let Some(Ok(SelectionOutcome::Preview(preview))) = original.selection_returned.get() {
        let raw = serde_json::to_string(&PreviewWire::from_preview(preview)).map_err(|_| "preview-output-encoding")?;
        require(raw.len() <= 16 * 1024, "preview-output-bounds")?;
        // The outer ORIGINAL owner binds these bytes, the actual source,
        // compiler inputs and the real exit before later supplying this DATA.
        println!("\nMRK_WINDOWS_SELECTION_PREVIEW_V1={raw}");
    }
    if matches!(case, Case::StopOld | Case::StopNew) {
        let run = observed.recovery_run.as_deref().ok_or("actual-recovery-run-missing")?;
        require(data::recovery_id(run), "actual-recovery-run-shape")?;
        // Copied name only: OUTER must observe this exact task-owned directory
        // and records before supplying it to the later recovery invocation.
        println!("\nMRK_WINDOWS_SELECTION_RECOVERY_V1={run}");
    }
    println!("\n{SELECTION_ACCOUNTING_PREFIX}{accounting}");
    let report = &observed.report;
    println!("\nMRK_WINDOWS_SELECTION_CASE_V1=case={};disposition={:?};inputs={};runtime={};closedRecords={};phaseMask={};charged={};confirmed={};originalWatchdogJoined=true;nativeSettled=true",
        case.label(), report.disposition, observed.input_rows_verified, observed.runtime_rows_verified,
        report.completely_closed_records, report.completely_closed_phase_mask,
        report.output_bytes_charged, report.output_bytes_confirmed);
    Ok(())
}

macro_rules! fixed_case {
    ($name:ident, $case:ident) => {
        #[test]
        #[ignore = "real fixed Windows selection fixture; separate original-owned process with actual prior preview"]
        fn $name() -> Result<(), &'static str> { run(Case::$case) }
    };
}
fixed_case!(preview_fresh, PreviewFresh);
fixed_case!(select_fresh, SelectFresh);
fixed_case!(preview_reuse, PreviewReuse);
fixed_case!(select_reuse, SelectReuse);
fixed_case!(preview_verify_reuse, PreviewVerifyReuse);
fixed_case!(verify_reuse, VerifyReuse);
fixed_case!(preview_remove_reuse, PreviewRemoveReuse);
fixed_case!(remove_reuse, RemoveReuse);
fixed_case!(refuse_stale_repair, RefuseStaleRepair);
fixed_case!(preview_repair_reuse, PreviewRepairReuse);
fixed_case!(repair_reuse, RepairReuse);
fixed_case!(preview_stop_old, PreviewStopOld);
fixed_case!(stop_old, StopOld);
fixed_case!(preview_previous, PreviewPrevious);
fixed_case!(recover_previous, RecoverPrevious);
fixed_case!(preview_stop_new, PreviewStopNew);
fixed_case!(stop_new, StopNew);
fixed_case!(preview_current, PreviewCurrent);
fixed_case!(recover_current, RecoverCurrent);
fixed_case!(preview_remove_damaged, PreviewRemoveDamaged);
fixed_case!(remove_damaged, RemoveDamaged);
fixed_case!(preview_registry_conflict, PreviewRegistryConflict);
fixed_case!(registry_conflict, RegistryConflict);
fixed_case!(refuse_foreign_selector, RefuseForeignSelector);

#[test]
fn preview_transport_is_not_a_mutation_or_extra_field_authority() {
    let preview = SelectionPreview {
        mode: SelectionMode::RemoveSelection, before_image: Some("a".repeat(64)), after_image: None,
        runtime: Some("b".repeat(64)), core_version: Some("1.2.3".to_owned()),
        shortcut_path: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Mobile Release Kit.lnk".to_owned(),
        registration_path: data::REGISTRATION, observation_sha256: "c".repeat(64),
        preserved_paths: vec![r"C:\fixed\installer-input".to_owned(), r"C:\fixed\runtime-input".to_owned(),
            r"C:\fixed\versions".to_owned(), r"C:\fixed\selection".to_owned()],
        retained_image_bytes_observed: None, warning: data::RECOVERY_WARNING,
    };
    let raw = serde_json::to_string(&PreviewWire::from_preview(&preview)).expect("inert DATA");
    assert_eq!(PreviewWire::decode(&raw, SelectionMode::RemoveSelection), Ok(preview));
    assert!(PreviewWire::decode(&raw, SelectionMode::RepairSameImage).is_err());
    let extra = raw.replacen('{', "{\"runArbitraryCommand\":true,", 1);
    assert!(PreviewWire::decode(&extra, SelectionMode::RemoveSelection).is_err());
    assert!(PreviewWire::decode(&(raw + "\n"), SelectionMode::RemoveSelection).is_err());
}
