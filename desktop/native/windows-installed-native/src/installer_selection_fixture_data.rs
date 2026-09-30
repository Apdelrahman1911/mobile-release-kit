//! Closed, nonshipping selection-fixture routing and observations only.
//! Eligibility strings/preview DATA do not authorize an original process,
//! native mutation, cleanup or installation. The accepted outer owner does.
use super::{Result, SelectionMode, SelectionReport};
use super::installer_fixture_data::{InstallerFixtureCase as InputCase, selection_fixture_process};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionFixturePoint { OldMoveReturned, NewMoveReturned, RegistryCommitReturned }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionFixtureCase {
    PreviewFresh, SelectFresh, PreviewReuse, SelectReuse,
    PreviewVerifyReuse, VerifyReuse, PreviewRemoveReuse, RemoveReuse,
    RefuseStaleRepair, PreviewRepairReuse, RepairReuse,
    PreviewStopOld, StopOld, PreviewPrevious, RecoverPrevious,
    PreviewStopNew, StopNew, PreviewCurrent, RecoverCurrent,
    PreviewRemoveDamaged, RemoveDamaged, PreviewRegistryConflict, RegistryConflict,
    RefuseForeignSelector,
}
impl SelectionFixtureCase {
    // Real episode order: TxR conflict needs the still-present B registration.
    // External task-owned damage/foreign setup is separately admitted by OUTER.
    pub const ALL: [Self; 24] = [
        Self::PreviewFresh, Self::SelectFresh, Self::PreviewReuse, Self::SelectReuse,
        Self::PreviewVerifyReuse, Self::VerifyReuse, Self::PreviewRemoveReuse, Self::RemoveReuse,
        Self::RefuseStaleRepair, Self::PreviewRepairReuse, Self::RepairReuse,
        Self::PreviewRegistryConflict, Self::RegistryConflict,
        Self::PreviewStopOld, Self::StopOld, Self::PreviewPrevious, Self::RecoverPrevious,
        Self::PreviewStopNew, Self::StopNew, Self::PreviewCurrent, Self::RecoverCurrent,
        Self::PreviewRemoveDamaged, Self::RemoveDamaged,
        Self::RefuseForeignSelector,
    ];
    pub fn label(self) -> &'static str { match self {
        Self::PreviewFresh=>"preview-fresh", Self::SelectFresh=>"select-fresh",
        Self::PreviewReuse=>"preview-reuse", Self::SelectReuse=>"select-reuse",
        Self::PreviewVerifyReuse=>"preview-verify-reuse", Self::VerifyReuse=>"verify-reuse",
        Self::PreviewRemoveReuse=>"preview-remove-reuse", Self::RemoveReuse=>"remove-reuse",
        Self::RefuseStaleRepair=>"refuse-stale-repair", Self::PreviewRepairReuse=>"preview-repair-reuse", Self::RepairReuse=>"repair-reuse",
        Self::PreviewStopOld=>"preview-stop-old", Self::StopOld=>"stop-old",
        Self::PreviewPrevious=>"preview-previous", Self::RecoverPrevious=>"recover-previous",
        Self::PreviewStopNew=>"preview-stop-new", Self::StopNew=>"stop-new",
        Self::PreviewCurrent=>"preview-current", Self::RecoverCurrent=>"recover-current",
        Self::PreviewRemoveDamaged=>"preview-remove-damaged", Self::RemoveDamaged=>"remove-damaged",
        Self::PreviewRegistryConflict=>"preview-registry-conflict", Self::RegistryConflict=>"registry-conflict",
        Self::RefuseForeignSelector=>"refuse-foreign-selector",
    } }
    pub fn app_test(self) -> &'static str { match self {
        Self::PreviewFresh=>"windows_installer_controller::selection_fixture::preview_fresh",
        Self::SelectFresh=>"windows_installer_controller::selection_fixture::select_fresh",
        Self::PreviewReuse=>"windows_installer_controller::selection_fixture::preview_reuse",
        Self::SelectReuse=>"windows_installer_controller::selection_fixture::select_reuse",
        Self::PreviewVerifyReuse=>"windows_installer_controller::selection_fixture::preview_verify_reuse",
        Self::VerifyReuse=>"windows_installer_controller::selection_fixture::verify_reuse",
        Self::PreviewRemoveReuse=>"windows_installer_controller::selection_fixture::preview_remove_reuse",
        Self::RemoveReuse=>"windows_installer_controller::selection_fixture::remove_reuse",
        Self::RefuseStaleRepair=>"windows_installer_controller::selection_fixture::refuse_stale_repair",
        Self::PreviewRepairReuse=>"windows_installer_controller::selection_fixture::preview_repair_reuse",
        Self::RepairReuse=>"windows_installer_controller::selection_fixture::repair_reuse",
        Self::PreviewStopOld=>"windows_installer_controller::selection_fixture::preview_stop_old",
        Self::StopOld=>"windows_installer_controller::selection_fixture::stop_old",
        Self::PreviewPrevious=>"windows_installer_controller::selection_fixture::preview_previous",
        Self::RecoverPrevious=>"windows_installer_controller::selection_fixture::recover_previous",
        Self::PreviewStopNew=>"windows_installer_controller::selection_fixture::preview_stop_new",
        Self::StopNew=>"windows_installer_controller::selection_fixture::stop_new",
        Self::PreviewCurrent=>"windows_installer_controller::selection_fixture::preview_current",
        Self::RecoverCurrent=>"windows_installer_controller::selection_fixture::recover_current",
        Self::PreviewRemoveDamaged=>"windows_installer_controller::selection_fixture::preview_remove_damaged",
        Self::RemoveDamaged=>"windows_installer_controller::selection_fixture::remove_damaged",
        Self::PreviewRegistryConflict=>"windows_installer_controller::selection_fixture::preview_registry_conflict",
        Self::RegistryConflict=>"windows_installer_controller::selection_fixture::registry_conflict",
        Self::RefuseForeignSelector=>"windows_installer_controller::selection_fixture::refuse_foreign_selector",
    } }
    pub fn input_case(self) -> InputCase { match self {
        Self::PreviewFresh | Self::SelectFresh => InputCase::Fresh,
        Self::PreviewStopOld | Self::StopOld | Self::PreviewPrevious | Self::RecoverPrevious => InputCase::WrongCaller,
        Self::PreviewStopNew | Self::StopNew | Self::PreviewCurrent | Self::RecoverCurrent
            | Self::PreviewRemoveDamaged | Self::RemoveDamaged => InputCase::BadManifest,
        _ => InputCase::Reuse,
    } }
    pub fn mode(self) -> SelectionMode { match self {
        Self::PreviewFresh | Self::SelectFresh | Self::PreviewReuse | Self::SelectReuse
            | Self::PreviewStopOld | Self::StopOld | Self::PreviewStopNew | Self::StopNew => SelectionMode::InstallActivated,
        Self::PreviewPrevious | Self::RecoverPrevious => SelectionMode::RecoverPrevious,
        Self::PreviewCurrent | Self::RecoverCurrent => SelectionMode::RecoverCurrent,
        Self::PreviewRemoveReuse | Self::RemoveReuse | Self::PreviewRemoveDamaged | Self::RemoveDamaged
            | Self::PreviewRegistryConflict | Self::RegistryConflict => SelectionMode::RemoveSelection,
        _ => SelectionMode::RepairSameImage,
    } }
    pub fn preview(self) -> bool { matches!(self,
        Self::PreviewFresh | Self::PreviewReuse | Self::PreviewVerifyReuse | Self::PreviewRemoveReuse
        | Self::PreviewRepairReuse | Self::PreviewStopOld | Self::PreviewPrevious
        | Self::PreviewStopNew | Self::PreviewCurrent | Self::PreviewRemoveDamaged | Self::PreviewRegistryConflict
        | Self::RefuseForeignSelector) }
    pub fn acquires(self) -> bool { self.mode() == SelectionMode::InstallActivated && !self.preview() }
    pub fn stop_point(self) -> Option<SelectionFixturePoint> { match self {
        Self::StopOld => Some(SelectionFixturePoint::OldMoveReturned),
        Self::StopNew => Some(SelectionFixturePoint::NewMoveReturned),
        _ => None,
    } }
}
pub fn selection_fixture_eligibility(case: SelectionFixtureCase) -> Result<PathBuf> {
    selection_fixture_process(case.app_test())
}

/// Copies of completed original-owner observations. They authorize nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionFixtureObservation {
    pub report: SelectionReport,
    /// Copy of this actual owner's generated recovery name, not path custody.
    pub recovery_run: Option<String>,
    pub input_rows_verified: usize,
    pub runtime_rows_verified: usize,
    pub readonly_originals_closed: bool,
    pub registry_conflict_staged: bool,
    pub registry_conflict_returned: bool,
    pub registry_competitor_closed: bool,
    pub registry_competitor_output: Option<SelectionReport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_fixed_routes_are_unique_and_only_two_stop_points_are_armed() {
        let labels: std::collections::BTreeSet<_> = SelectionFixtureCase::ALL.iter().map(|c| c.label()).collect();
        let tests: std::collections::BTreeSet<_> = SelectionFixtureCase::ALL.iter().map(|c| c.app_test()).collect();
        assert_eq!(labels.len(), 24); assert_eq!(tests.len(), 24);
        assert_eq!(SelectionFixtureCase::ALL.iter().filter(|c| c.acquires()).count(), 4);
        assert_eq!(SelectionFixtureCase::ALL.iter().filter(|c| c.stop_point().is_some()).count(), 2);
        assert_eq!(SelectionFixtureCase::RegistryConflict.mode(), SelectionMode::RemoveSelection);
    }
}

// Closed fixture-only observation transport. This is copied DATA after the real
// controller/watchdog and native originals settle; no path here grants custody.
pub const SELECTION_FIXTURE_PROFILE: &str = "windows-installer-selection-v1";
pub const SELECTION_ACCOUNTING_PREFIX: &str = "MRK_WINDOWS_SELECTION_ACCOUNTING_V1=";
pub const SELECTION_ACCOUNTING_LIMIT: usize = 16 * 1024;
pub const SELECTION_OUTPUT_LIMIT: usize = 24;
pub const SELECTION_ACCOUNTING_HEAD: &[&str] = &[
    "version", "profile", "sourceSha", "sourceTree", "runId", "attempt", "case",
    "previewObservationSha256", "recoveryRun", "inputs", "runtime", "readonlyClosed",
    "conflictStaged", "conflictReturned", "competitorClosed", "competitorPresent",
];
pub const SELECTION_ACCOUNTING_REPORT: &[&str] = &[
    "mode", "stage", "disposition", "firstFailure", "oldMoveEntered", "newMoveEntered",
    "registryCommitEntered", "registryCommitted", "nativeClosed", "oldMoveNative",
    "newMoveNative", "registryNative", "flushedRecords", "closedRecords", "phaseMask",
    "writeCountUnknown", "charged", "confirmed", "retainedBytes",
    "controllerFinalityRequired", "shippingInstallerEnabled", "outputs",
];
pub const SELECTION_ACCOUNTING_OUTPUT: &[&str] = &["kind", "path", "destination", "native"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionAccountingOutput {
    pub kind: super::installer_selection_data::OutputKind,
    pub path: String,
    pub destination: Option<String>,
    pub native_return: (i32, u32),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionAccounting {
    // Exact keys were consumed in canonical order; absent nullable properties
    // are rejected, rather than silently becoming Option::None.
    pub fields: std::collections::BTreeMap<String, String>,
    pub outputs: Vec<SelectionAccountingOutput>,
    pub competitor_outputs: Vec<SelectionAccountingOutput>,
}
fn accounting_need(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(super::Error::Unsafe) }
}
fn accounting_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn accounting_number(value: &str, limit: u64) -> Result<u64> {
    accounting_need(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0')) && value.len() <= 20)?;
    let number = value.parse::<u64>().map_err(|_| super::Error::Bounds)?;
    accounting_need(number <= limit)?; Ok(number)
}
fn accounting_return(value: &str) -> Result<Option<(i32, u32)>> {
    if value == "-" { return Ok(None); }
    let (first, second) = value.split_once(',').ok_or(super::Error::Unsafe)?;
    let returned = first.parse::<i32>().map_err(|_| super::Error::Unsafe)?;
    let error = accounting_number(second, u32::MAX as u64)? as u32;
    accounting_need(first == returned.to_string())?;
    Ok(Some((returned, error)))
}
/// Namespace-relative descriptions only, never a general path grammar.
pub fn selection_accounting_role(value: &str) -> bool {
    use super::installer_selection_data as d;
    let parts: Vec<_> = value.split('/').collect();
    match parts.as_slice() {
        ["selector"] | ["selection"] | ["selection", "recovery"] => true,
        ["selection", "recovery", run] => d::recovery_id(run),
        ["selection", "recovery", run, leaf] => d::recovery_id(run)
            && (matches!(*leaf, "incoming.lnk" | "previous.lnk")
                || (0..d::PHASES.len()).any(|i| *leaf == format!("record-{i:02}.bin"))),
        ["selection", target] => *target == d::TARGET,
        ["selection", target, image] => *target == d::TARGET && d::digest(image),
        ["selection", target, image, leaf] => *target == d::TARGET && d::digest(image)
            && matches!(*leaf, "profile.json" | "launch.lnk"),
        _ => false,
    }
}
fn accounting_role(path: &str, preview: Option<&super::SelectionPreview>) -> Result<String> {
    use super::installer_selection_data as d;
    let preview = preview.ok_or(super::Error::Unsafe)?;
    accounting_need(preview.preserved_paths.len() == 4 && d::native_dos_path(path)
        && d::native_dos_path(&preview.shortcut_path))?;
    let root = preview.preserved_paths[0].strip_suffix(r"\installer-input").ok_or(super::Error::Unsafe)?;
    accounting_need(d::native_dos_path(root) && root.ends_with(r"\Mobile Release Kit")
        && ["installer-input", "runtime-input", "versions", "selection"].iter()
            .zip(&preview.preserved_paths).all(|(name, actual)| *actual == format!(r"{root}\{name}")))?;
    let role = if path == preview.shortcut_path { "selector".to_owned() }
        else if path == preview.preserved_paths[3] { "selection".to_owned() }
        else {
            let relative = path.strip_prefix(&(preview.preserved_paths[3].clone() + "\\"))
                .ok_or(super::Error::Unsafe)?;
            format!("selection/{}", relative.replace('\\', "/"))
        };
    accounting_need(selection_accounting_role(&role))?; Ok(role)
}
fn accounting_report_fields(rows: &mut Vec<(String, String)>, prefix: &str,
    report: &SelectionReport, preview: Option<&super::SelectionPreview>) -> Result<()> {
    let pair = |value: Option<(i32, u32)>| value.map_or_else(|| "-".to_owned(), |(v, e)| format!("{v},{e}"));
    let values = vec![
        report.mode.name().to_owned(), format!("{:?}", report.stage), format!("{:?}", report.disposition),
        report.first_failure.unwrap_or("-").to_owned(), report.old_move_entered.to_string(),
        report.new_move_entered.to_string(), report.registry_commit_entered.to_string(),
        report.registry_committed.to_string(), report.native_closed.to_string(),
        pair(report.old_move_native), pair(report.new_move_native), pair(report.registry_native),
        report.os_flush_acknowledged_records.to_string(), report.completely_closed_records.to_string(),
        report.completely_closed_phase_mask.to_string(), report.write_count_unknown.to_string(),
        report.output_bytes_charged.to_string(), report.output_bytes_confirmed.to_string(),
        report.retained_image_bytes_observed.map_or_else(|| "-".to_owned(), |v| v.to_string()),
        report.controller_finality_required.to_string(), report.shipping_installer_enabled.to_string(),
        report.outputs.len().to_string(),
    ];
    accounting_need(values.len() == SELECTION_ACCOUNTING_REPORT.len() && report.outputs.len() <= SELECTION_OUTPUT_LIMIT)?;
    for (key, value) in SELECTION_ACCOUNTING_REPORT.iter().zip(values) { rows.push((format!("{prefix}.{key}"), value)); }
    for (i, output) in report.outputs.iter().enumerate() {
        let values = [format!("{:?}", output.kind), accounting_role(&output.path, preview)?,
            match &output.destination { Some(path) => accounting_role(path, preview)?, None => "-".to_owned() },
            pair(output.native_return)];
        for (key, value) in SELECTION_ACCOUNTING_OUTPUT.iter().zip(values) {
            rows.push((format!("{prefix}.o{i}.{key}"), value));
        }
    }
    Ok(())
}
pub fn selection_accounting_encode(case: SelectionFixtureCase, observed: &SelectionFixtureObservation,
    preview: Option<&super::SelectionPreview>) -> Result<String> {
    let source_tree = std::env::var("MRK_WINDOWS_SOURCE_TREE").map_err(|_| super::Error::Unsafe)?;
    let run = std::env::var("GITHUB_RUN_ID").map_err(|_| super::Error::Unsafe)?;
    let values = vec![
        "1".to_owned(), SELECTION_FIXTURE_PROFILE.to_owned(), env!("GITHUB_SHA").to_owned(), source_tree, run,
        "1".to_owned(), case.label().to_owned(),
        preview.map_or_else(|| "-".to_owned(), |p| p.observation_sha256.clone()),
        observed.recovery_run.clone().unwrap_or_else(|| "-".to_owned()),
        observed.input_rows_verified.to_string(), observed.runtime_rows_verified.to_string(),
        observed.readonly_originals_closed.to_string(), observed.registry_conflict_staged.to_string(),
        observed.registry_conflict_returned.to_string(), observed.registry_competitor_closed.to_string(),
        observed.registry_competitor_output.is_some().to_string(),
    ];
    let mut rows: Vec<_> = SELECTION_ACCOUNTING_HEAD.iter().zip(values).map(|(k, v)| ((*k).to_owned(), v)).collect();
    accounting_report_fields(&mut rows, "main", &observed.report, preview)?;
    if let Some(report) = &observed.registry_competitor_output {
        accounting_report_fields(&mut rows, "competitor", report, preview)?;
    }
    let line = rows.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(";");
    SelectionAccounting::parse(&line)?;
    Ok(line)
}
impl SelectionAccounting {
    pub fn get(&self, key: &str) -> Result<&str> {
        self.fields.get(key).map(String::as_str).ok_or(super::Error::Unsafe)
    }
    pub fn number(&self, key: &str, limit: u64) -> Result<u64> { accounting_number(self.get(key)?, limit) }
    pub fn parse(raw: &str) -> Result<Self> {
        use super::installer_selection_data as d;
        accounting_need(!raw.is_empty() && raw.len() <= SELECTION_ACCOUNTING_LIMIT
            && raw.bytes().all(|b| (32..=126).contains(&b)))?;
        let mut source = raw.split(';');
        let mut fields = std::collections::BTreeMap::new();
        fn take<'a>(source: &mut std::str::Split<'a, char>, fields: &mut std::collections::BTreeMap<String, String>,
            key: &str) -> Result<String> {
            let (name, value) = source.next().and_then(|s| s.split_once('=')).ok_or(super::Error::Unsafe)?;
            accounting_need(name == key && !value.is_empty() && !value.contains('=')
                && !fields.contains_key(key))?;
            fields.insert(key.to_owned(), value.to_owned()); Ok(value.to_owned())
        }
        for key in SELECTION_ACCOUNTING_HEAD { take(&mut source, &mut fields, key)?; }
        let get = |key: &str| fields.get(key).map(String::as_str).ok_or(super::Error::Unsafe);
        accounting_need(get("version")? == "1" && get("profile")? == SELECTION_FIXTURE_PROFILE
            && accounting_hex(get("sourceSha")?, 40) && accounting_hex(get("sourceTree")?, 40)
            && accounting_number(get("runId")?, u64::MAX)? > 0 && get("attempt")? == "1")?;
        let case = SelectionFixtureCase::ALL.iter().copied().find(|c| c.label() == get("case").unwrap_or(""))
            .ok_or(super::Error::Unsafe)?;
        let observation = get("previewObservationSha256")?;
        accounting_need(if case == SelectionFixtureCase::RefuseForeignSelector { observation == "-" }
            else { d::digest(observation) })?;
        accounting_need(get("recoveryRun")? == "-" || d::recovery_id(get("recoveryRun")?))?;
        accounting_number(get("inputs")?, 54)?; accounting_number(get("runtime")?, 47)?;
        for key in ["readonlyClosed", "competitorClosed"] { accounting_need(get(key)? == "true")?; }
        for key in ["conflictStaged", "conflictReturned", "competitorPresent"] {
            accounting_need(matches!(get(key)?, "true" | "false"))?;
        }
        let competitor = get("competitorPresent")? == "true";
        accounting_need(competitor == (case == SelectionFixtureCase::RegistryConflict)
            && (get("conflictStaged")? == "true") == competitor && (get("conflictReturned")? == "true") == competitor)?;
        let mut parsed = Vec::new();
        for prefix in if competitor { &["main", "competitor"][..] } else { &["main"][..] } {
            for key in SELECTION_ACCOUNTING_REPORT {
                take(&mut source, &mut fields, &format!("{prefix}.{key}"))?;
            }
            let get = |key: &str| fields.get(&format!("{prefix}.{key}")).map(String::as_str).ok_or(super::Error::Unsafe);
            accounting_need(get("mode")? == case.mode().name()
                && matches!(get("stage")?, "Fresh" | "Observed" | "RegistryStaged" | "BackupIntentFlushed"
                    | "BackupReturned" | "SelectIntentFlushed" | "SelectReturned" | "RegistryIntentFlushed"
                    | "RegistryReturned" | "Closed")
                && matches!(get("disposition")?, "Unchanged" | "Selected" | "LaunchEntriesRemoved" | "Partial"))?;
            let failure = get("firstFailure")?;
            accounting_need(failure == "-" || (failure.len() <= 96 && failure.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')))?;
            for key in ["oldMoveEntered", "newMoveEntered", "registryCommitEntered", "registryCommitted"] {
                accounting_need(matches!(get(key)?, "true" | "false"))?;
            }
            // The competitor's report is its original staging/write account,
            // not a fabricated SelectionOwner settlement. Its actual closure is
            // the separate mandatory competitorClosed observation above.
            accounting_need(get("nativeClosed")? == if *prefix == "main" { "true" } else { "false" }
                && get("writeCountUnknown")? == "false"
                && get("controllerFinalityRequired")? == "true" && get("shippingInstallerEnabled")? == "false")?;
            for key in ["oldMoveNative", "newMoveNative", "registryNative"] { accounting_return(get(key)?)?; }
            let flushed = accounting_number(get("flushedRecords")?, 7)?;
            let closed = accounting_number(get("closedRecords")?, 7)?;
            let mask = accounting_number(get("phaseMask")?, 127)?;
            accounting_need(closed <= flushed && mask.count_ones() as u64 == closed)?;
            let charged = accounting_number(get("charged")?, d::OUTPUT_LIMIT)?;
            accounting_need(accounting_number(get("confirmed")?, d::OUTPUT_LIMIT)? <= charged)?;
            if get("retainedBytes")? != "-" { accounting_number(get("retainedBytes")?, 2 * 1024 * 1024 * 1024)?; }
            let count = accounting_number(get("outputs")?, SELECTION_OUTPUT_LIMIT as u64)? as usize;
            let mut outputs = Vec::new();
            for i in 0..count {
                let values = SELECTION_ACCOUNTING_OUTPUT.iter().map(|key|
                    take(&mut source, &mut fields, &format!("{prefix}.o{i}.{key}"))).collect::<Result<Vec<_>>>()?;
                let kind = match values[0].as_str() {
                    "CreatedDirectory" => d::OutputKind::CreatedDirectory,
                    "CreatedFile" => d::OutputKind::CreatedFile, "Rename" => d::OutputKind::Rename,
                    _ => return Err(super::Error::Unsafe),
                };
                accounting_need(selection_accounting_role(&values[1]))?;
                let destination = if values[2] == "-" { None } else {
                    accounting_need(selection_accounting_role(&values[2]))?; Some(values[2].clone())
                };
                accounting_need((kind == d::OutputKind::Rename) == destination.is_some())?;
                let native_return = accounting_return(&values[3])?.ok_or(super::Error::Unsafe)?;
                outputs.push(SelectionAccountingOutput { kind, path: values[1].clone(), destination, native_return });
            }
            parsed.push(outputs);
        }
        accounting_need(source.next().is_none() && parsed.iter().map(Vec::len).sum::<usize>() <= SELECTION_OUTPUT_LIMIT)?;
        let mut parsed = parsed.into_iter();
        Ok(Self { fields, outputs: parsed.next().ok_or(super::Error::Unsafe)?,
            competitor_outputs: parsed.next().unwrap_or_default() })
    }
}

/// Canonical dependency order, not executable process instructions.
pub const SELECTION_EPISODE_ROLES: [&str; 54] = [
    "stage-fresh",
    "preview-fresh",
    "preview-fresh-observe",
    "select-fresh",
    "select-fresh-observe",
    "stage-reuse",
    "preview-reuse",
    "preview-reuse-observe",
    "select-reuse",
    "select-reuse-observe",
    "preview-verify-reuse",
    "preview-verify-reuse-observe",
    "verify-reuse",
    "verify-reuse-observe",
    "preview-remove-reuse",
    "preview-remove-reuse-observe",
    "remove-reuse",
    "remove-reuse-observe",
    "refuse-stale-repair",
    "refuse-stale-repair-observe",
    "preview-repair-reuse",
    "preview-repair-reuse-observe",
    "repair-reuse",
    "repair-reuse-observe",
    "preview-registry-conflict",
    "preview-registry-conflict-observe",
    "registry-conflict",
    "registry-conflict-observe",
    "stage-wrong-caller",
    "preview-stop-old",
    "preview-stop-old-observe",
    "stop-old",
    "stop-old-observe",
    "preview-previous",
    "preview-previous-observe",
    "recover-previous",
    "recover-previous-observe",
    "stage-bad-manifest",
    "preview-stop-new",
    "preview-stop-new-observe",
    "stop-new",
    "stop-new-observe",
    "preview-current",
    "preview-current-observe",
    "recover-current",
    "recover-current-observe",
    "damage-owned-shell",
    "preview-remove-damaged",
    "preview-remove-damaged-observe",
    "remove-damaged",
    "remove-damaged-observe",
    "stage-owned-foreign-selector",
    "refuse-foreign-selector",
    "refuse-foreign-selector-observe",
];
pub fn selection_native_test(role: &str) -> Result<&'static str> {
    match role {
        "stage-fresh" => Ok("qualification_fixture::installer::selection::stage_fresh"),
        "preview-fresh-observe" => Ok("qualification_fixture::installer::selection::observe_preview_fresh"),
        "select-fresh-observe" => Ok("qualification_fixture::installer::selection::observe_select_fresh"),
        "stage-reuse" => Ok("qualification_fixture::installer::selection::stage_reuse"),
        "preview-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_preview_reuse"),
        "select-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_select_reuse"),
        "preview-verify-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_preview_verify_reuse"),
        "verify-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_verify_reuse"),
        "preview-remove-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_preview_remove_reuse"),
        "remove-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_remove_reuse"),
        "refuse-stale-repair-observe" => Ok("qualification_fixture::installer::selection::observe_refuse_stale_repair"),
        "preview-repair-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_preview_repair_reuse"),
        "repair-reuse-observe" => Ok("qualification_fixture::installer::selection::observe_repair_reuse"),
        "preview-registry-conflict-observe" => Ok("qualification_fixture::installer::selection::observe_preview_registry_conflict"),
        "registry-conflict-observe" => Ok("qualification_fixture::installer::selection::observe_registry_conflict"),
        "stage-wrong-caller" => Ok("qualification_fixture::installer::selection::stage_wrong_caller"),
        "preview-stop-old-observe" => Ok("qualification_fixture::installer::selection::observe_preview_stop_old"),
        "stop-old-observe" => Ok("qualification_fixture::installer::selection::observe_stop_old"),
        "preview-previous-observe" => Ok("qualification_fixture::installer::selection::observe_preview_previous"),
        "recover-previous-observe" => Ok("qualification_fixture::installer::selection::observe_recover_previous"),
        "stage-bad-manifest" => Ok("qualification_fixture::installer::selection::stage_bad_manifest"),
        "preview-stop-new-observe" => Ok("qualification_fixture::installer::selection::observe_preview_stop_new"),
        "stop-new-observe" => Ok("qualification_fixture::installer::selection::observe_stop_new"),
        "preview-current-observe" => Ok("qualification_fixture::installer::selection::observe_preview_current"),
        "recover-current-observe" => Ok("qualification_fixture::installer::selection::observe_recover_current"),
        "damage-owned-shell" => Ok("qualification_fixture::installer::selection::damage_owned_shell"),
        "preview-remove-damaged-observe" => Ok("qualification_fixture::installer::selection::observe_preview_remove_damaged"),
        "remove-damaged-observe" => Ok("qualification_fixture::installer::selection::observe_remove_damaged"),
        "stage-owned-foreign-selector" => Ok("qualification_fixture::installer::selection::stage_owned_foreign_selector"),
        "refuse-foreign-selector-observe" => Ok("qualification_fixture::installer::selection::observe_refuse_foreign_selector"),
        _ => Err(super::Error::Unsafe),
    }
}


#[cfg(test)]
mod accounting_data_tests {
    use super::*;
    fn fresh() -> String {
        let head = [
            "1".to_owned(), SELECTION_FIXTURE_PROFILE.to_owned(), "a".repeat(40), "b".repeat(40),
            "19".to_owned(), "1".to_owned(), "preview-fresh".to_owned(), "e".repeat(64),
            "-".to_owned(), "0".to_owned(), "0".to_owned(), "true".to_owned(),
            "false".to_owned(), "false".to_owned(), "true".to_owned(), "false".to_owned(),
        ];
        let report = [
            "install-activated", "Observed", "Unchanged", "-", "false", "false", "false", "false",
            "true", "-", "-", "-", "0", "0", "0", "false", "0", "0", "-", "true", "false", "0",
        ];
        SELECTION_ACCOUNTING_HEAD.iter().zip(head).map(|(k,v)| format!("{k}={v}"))
            .chain(SELECTION_ACCOUNTING_REPORT.iter().zip(report).map(|(k,v)| format!("main.{k}={v}")))
            .collect::<Vec<_>>().join(";")
    }
    #[test]
    fn explicit_null_order_bounds_and_finality_are_not_inferred() -> Result<()> {
        let raw = fresh();
        let parsed = SelectionAccounting::parse(&raw)?;
        assert_eq!(parsed.get("main.oldMoveNative")?, "-");
        assert_eq!(parsed.get("main.retainedBytes")?, "-");
        assert!(parsed.outputs.is_empty());
        for bad in [
            raw.replace("main.oldMoveNative=-;", ""),
            raw.replace("main.retainedBytes=-", "main.retainedBytes="),
            raw.replace("main.nativeClosed=true", "main.nativeClosed=false"),
            raw.replace("readonlyClosed=true", "readonlyClosed=false"),
            raw.replace("competitorClosed=true", "competitorClosed=false"),
            raw.replace("main.writeCountUnknown=false", "main.writeCountUnknown=true"),
            raw.replace("main.controllerFinalityRequired=true", "main.controllerFinalityRequired=false"),
            raw.replace("version=1;profile=", "version=1;version=1;profile="),
            raw.clone() + ";unknown=1", raw.clone() + "\n", "x".repeat(SELECTION_ACCOUNTING_LIMIT+1),
        ] { assert!(SelectionAccounting::parse(&bad).is_err()); }
        Ok(())
    }
    #[test]
    fn output_destinations_are_closed_namespace_data_not_path_permissions() -> Result<()> {
        let raw = fresh().replace("main.outputs=0", "main.outputs=1");
        let good = raw.clone() + ";main.o0.kind=CreatedFile;main.o0.path=selector;main.o0.destination=-;main.o0.native=1,0";
        let parsed = SelectionAccounting::parse(&good)?;
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].native_return, (1,0));
        for bad in [
            good.replace("main.o0.path=selector", "main.o0.path=C:\\arbitrary\\file"),
            good.replace("main.o0.path=selector", "main.o0.path=selection/../file"),
            good.replace("main.o0.path=selector", "main.o0.path=selection/recovery/not-a-run/profile.json"),
            good.replace("main.o0.destination=-", "main.o0.destination=selector"),
            good.replace("main.o0.kind=CreatedFile", "main.o0.kind=Delete"),
            good.replace("main.o0.native=1,0", "main.o0.native=-"),
            good.replace("main.o0.native=1,0", "main.o0.native=01,0"),
            good.replace("main.outputs=1", "main.outputs=25"),
        ] { assert!(SelectionAccounting::parse(&bad).is_err()); }
        assert!(selection_accounting_role(&format!("selection/recovery/{}/record-06.bin", "1".repeat(32))));
        assert!(!selection_accounting_role(&format!("selection/recovery/{}/record-07.bin", "1".repeat(32))));
        Ok(())
    }
}
