
//! Finite independent observations for the actual24 selection episode.
//! Uses the existing original Fixture, files, native arenas and 90s endpoint.
//! No runtime/vendor launch, generic path/action entry, new process controller,
//! destructive teardown, or shortcut resolution is provided.
use super::*;
use super::super::super::installer_fixture_data::selection_fixture_process;
use super::super::super::installer_selection_data as d;
use super::super::super::installer_selection_fixture_data::{
    SelectionFixtureCase as SelectionCase, SelectionAccounting, SELECTION_ACCOUNTING_PREFIX,
    SELECTION_EPISODE_ROLES, SELECTION_FIXTURE_PROFILE, selection_native_test,
};
use super::super::super::installer_selection::fixture_observation::{
    self as primitives, Observer, RegistrationObservation, FOREIGN_IMAGE,
};
use std::cell::RefCell;

const HEADER: &str = "MRK_WINDOWS_SELECTION_SNAPSHOT_V1";
const KEYS: &[&str] = &[
    "profile", "sourceSha", "sourceTree", "runId", "attempt", "role",
    "precheckSha256", "profilesSha256", "rosterSha256", "programFiles", "commonPrograms",
    "candidate", "freshMrkAbsent", "selectorImage", "registrationImage",
    "registrationSha256", "registrationSecurityDigest", "registrationParentSha256",
    "registrationWrite", "trees", "objects", "damagedShell", "foreignSelector",
    "accountedRuns", "fileOriginals", "fileOriginalsClosed", "parentBookSettled",
    "selectionPrimitivesClosed", "unknown", "resultCloseGate",
];
const APP_PREFIX: &str = "MRK_WINDOWS_SELECTION_CASE_V1=";
const APP_KEYS: &[&str] = &["case", "disposition", "inputs", "runtime", "closedRecords",
    "phaseMask", "charged", "confirmed", "originalWatchdogJoined", "nativeSettled"];
const SOURCES: [Case; 4] = [Case::Fresh, Case::Reuse, Case::WrongCaller, Case::BadManifest];
const MAX_RUNS: usize = 10;
const MAX_OBJECTS: usize = 130;
const IMAGE_DIRECTORIES: usize = 7;

// Exact successful OriginalFile-acquisition bound for ONE closed native role.
// This is not the simultaneous-live count. Metadata, ACL/token/native registry
// and COM calls borrow their own retained primitives and do not increment it.
// All complete rosters are walked; there is no sampling or inventory omission.
// - root private + ProgramFiles ancestry: <=27, or <=19 before staging (so its
//   ten local dirs, nine destination dirs and two leaves fit the existing40);
// - precheck+compiled image2, each preceding app output+exit2, previous snapshot+exit2;
// - source63 (9dirs+54readers), image66 (12dirs+54readers), runtime52 (5+47);
// - OS System/CommonPrograms ancestry16, selector1 if present, shared7;
// - selection/target/recovery3, each provenance3, each run directory+its exact
//   recorded phase files and retained links. Final10 runs contain52 files;
// - staging reuses its postwrite roster:181 versus63, i.e.118 additional opens;
// - owned damage adds a current complete image66 and reader/writer/readback3;
// - fixed foreign setup adds Programs ancestry8 and create/readback2;
// - initial fresh admission additionally reads Programs ancestry8 BEFORE staging.
// The final proof writer is the unchanged write_fixture_record original owner,
// after Fixture settlement; it is not charged to Fixture.opened.
// Maximum is804 at owned damage; stage-bad-manifest753, final observer748, foreign756.
// Default256, simultaneous-live40, COM32 and the SAME90s endpoint are unchanged.
pub(super) const LIFETIME_OPENS: usize = 804;
fn old_move(case: SelectionCase) -> bool {
    matches!(case, SelectionCase::SelectReuse | SelectionCase::RemoveReuse | SelectionCase::StopOld
        | SelectionCase::StopNew | SelectionCase::RecoverCurrent | SelectionCase::RemoveDamaged)
}
fn open_budget(role: &str) -> Result<usize> {
    let position = role_position(role)?;
    let prefix = &SELECTION_EPISODE_ROLES[..=position];
    let apps: Vec<_> = prefix.iter().filter_map(|r| role_case(r)).collect();
    let sources = SOURCES.iter().filter(|c| prefix.contains(&source_stage(**c))).count();
    let images = SOURCES.iter().filter(|c| apps.contains(&source_selection(**c))).count();
    let stage = SOURCES.iter().any(|c| role == source_stage(*c));
    let (mut selector, mut registry) = (None, None);
    for case in &apps { apply_state(*case, &mut selector, &mut registry); }
    let foreign = prefix.contains(&"stage-owned-foreign-selector");
    let run_objects: usize = apps.iter().filter(|c| expected_phase_mask(**c) != 0 || **c == SelectionCase::RegistryConflict)
        .map(|c| 1 + expected_phase_mask(*c).count_ones() as usize + usize::from(old_move(*c))
            + usize::from(*c == SelectionCase::StopOld)).sum();
    let bound = if stage { 19 } else { 27 };
    let bound = bound + 2 + apps.len() * 2 + 2 * usize::from(position > 0)
        + sources * 63 + usize::from(stage) * 118 + images * 66
        + usize::from(images > 0) * (52 + 7 + 3) + images * 3
        + 16 + usize::from(selector.is_some() || foreign) + run_objects
        + usize::from(role == "stage-fresh") * 8 + usize::from(role == "damage-owned-shell") * 69
        + usize::from(role == "stage-owned-foreign-selector") * 10;
    need(bound <= LIFETIME_OPENS)?;
    Ok(bound)
}

struct Boundary<'a> { original: RefCell<&'a mut Fixture> }
impl super::super::super::InstallerBoundary for Boundary<'_> {
    fn producing_boundary(&self) -> Result<()> {
        self.original.try_borrow_mut().map_err(|_| Error::Unknown)?.gate()
    }
    fn settlement_boundary(&self) {
        // Same original absorbing latch. Expiry refuses new work but is not a
        // reason to skip a known consuming close. Any borrow invariant panic
        // reaches the enclosing retained-original Unknown path.
        let _ = self.original.borrow_mut().gate();
    }
}
fn role_position(role: &str) -> Result<usize> {
    SELECTION_EPISODE_ROLES.iter().position(|r| *r == role).ok_or(Error::Unsafe)
}
fn role_case(role: &str) -> Option<SelectionCase> {
    SelectionCase::ALL.iter().copied().find(|c| c.label() == role)
}
fn source_stage(case: Case) -> &'static str { match case {
    Case::Fresh => "stage-fresh", Case::Reuse => "stage-reuse",
    Case::WrongCaller => "stage-wrong-caller", Case::BadManifest => "stage-bad-manifest",
    Case::StopCopy => "not-an-admitted-selection-stage",
} }
fn source_selection(case: Case) -> SelectionCase { match case {
    Case::Fresh => SelectionCase::SelectFresh, Case::Reuse => SelectionCase::SelectReuse,
    Case::WrongCaller => SelectionCase::StopOld, Case::BadManifest => SelectionCase::StopNew,
    Case::StopCopy => SelectionCase::RefuseForeignSelector,
} }
fn result_name(role: &str) -> Result<String> {
    role_position(role)?; Ok(format!("retained-{role}.private.txt"))
}
fn image_data(input: &Inputs) -> d::ImageData {
    d::ImageData { image: input.image.to_owned(), runtime: input.manifest.to_owned(),
        core_version: input.core_version.to_owned(), profile: input.profile.to_vec(),
        input_hashes: input.hashes.map(str::to_owned), input_sizes: input.sizes,
        helper: input.helper.to_owned() }
}
fn one_line<'a>(text: &'a str, prefix: &str) -> Result<&'a str> {
    let mut matching = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = matching.next().ok_or(Error::Unsafe)?;
    need(matching.next().is_none() && !value.is_empty())?; Ok(value)
}
fn parse_app(raw: &[u8], case: SelectionCase, pre: &Wire) -> Result<SelectionAccounting> {
    need(!raw.is_empty() && raw.len() <= OWNER_LIMIT)?;
    let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
    let account = SelectionAccounting::parse(one_line(text, SELECTION_ACCOUNTING_PREFIX)?)?;
    for key in ["profile", "sourceSha", "sourceTree", "runId", "attempt"] {
        need(account.get(key)? == pre.get(key)?)?;
    }
    need(account.get("case")? == case.label())?;
    let proof = one_line(text, APP_PREFIX)?;
    let raw = format!("MRK_WINDOWS_SELECTION_CASE_DATA_V1\n{}\n", proof.replace(';', "\n"));
    let summary = Wire::parse(raw.as_bytes(), "MRK_WINDOWS_SELECTION_CASE_DATA_V1", APP_KEYS, LIMIT)?;
    summary.equal("case", case.label())?;
    summary.equal("originalWatchdogJoined", "true")?; summary.equal("nativeSettled", "true")?;
    for (plain, copied) in [("disposition", "main.disposition"), ("inputs", "inputs"), ("runtime", "runtime"),
        ("closedRecords", "main.closedRecords"), ("phaseMask", "main.phaseMask"),
        ("charged", "main.charged"), ("confirmed", "main.confirmed")] {
        summary.equal(plain, account.get(copied)?)?;
    }
    let expected_preview = case.preview() && case != SelectionCase::RefuseForeignSelector;
    need(text.lines().filter(|line| line.starts_with("MRK_WINDOWS_SELECTION_PREVIEW_V1=")).count()
        == usize::from(expected_preview))?;
    let expected_stop = matches!(case, SelectionCase::StopOld | SelectionCase::StopNew);
    need(text.lines().filter(|line| line.starts_with("MRK_WINDOWS_SELECTION_RECOVERY_V1=")).count()
        == usize::from(expected_stop))?;
    if expected_stop {
        need(one_line(text, "MRK_WINDOWS_SELECTION_RECOVERY_V1=")? == account.get("recoveryRun")?)?;
    }
    validate_account(case, &account)?;
    Ok(account)
}
fn validate_account(case: SelectionCase, value: &SelectionAccounting) -> Result<()> {
    let equal = |key: &str, expected: &str| need(value.get(key)? == expected);
    let no_moves = || -> Result<()> {
        for key in ["main.oldMoveEntered", "main.newMoveEntered", "main.registryCommitEntered", "main.registryCommitted"] {
            equal(key, "false")?;
        }
        for key in ["main.oldMoveNative", "main.newMoveNative", "main.registryNative"] { equal(key, "-")?; }
        Ok(())
    };
    let readonly = || -> Result<()> { equal("inputs", "54")?; equal("runtime", "47") };
    let no_output = || -> Result<()> {
        need(value.outputs.is_empty() && value.get("recoveryRun")? == "-")?;
        for key in ["main.charged", "main.confirmed", "main.closedRecords", "main.flushedRecords", "main.phaseMask"] {
            equal(key, "0")?;
        }
        Ok(())
    };
    need(value.outputs.iter().chain(&value.competitor_outputs).all(|v| v.native_return == (1, 0)))?;
    need(value.competitor_outputs.is_empty())?;
    if case.preview() && case != SelectionCase::RefuseForeignSelector {
        no_moves()?; no_output()?; equal("main.disposition", "Unchanged")?; equal("main.firstFailure", "-")?;
        if matches!(case.mode(), d::Mode::RepairSameImage | d::Mode::RecoverPrevious | d::Mode::RecoverCurrent) { readonly()?; }
        else { equal("inputs", "0")?; equal("runtime", "0")?; }
    } else {
        match case {
            SelectionCase::RefuseForeignSelector | SelectionCase::RefuseStaleRepair => {
                no_moves()?; no_output()?; equal("main.disposition", "Unchanged")?;
                need(value.get("main.firstFailure")? != "-")?;
            },
            SelectionCase::RegistryConflict => {
                no_moves()?; equal("main.disposition", "Unchanged")?;
                need(value.get("main.firstFailure")? != "-" && d::recovery_id(value.get("recoveryRun")?)
                    && value.outputs.len() == 1 && value.outputs[0].kind == d::OutputKind::CreatedDirectory
                    && value.outputs[0].path == format!("selection/recovery/{}", value.get("recoveryRun")?)
                    && value.number("competitor.charged", d::OUTPUT_LIMIT)? > 0
                    && value.get("competitor.charged")? == value.get("competitor.confirmed")?)?;
                for key in ["main.closedRecords", "main.flushedRecords", "main.phaseMask", "main.charged", "main.confirmed"] {
                    equal(key, "0")?;
                }
            },
            SelectionCase::StopOld | SelectionCase::StopNew => {
                readonly()?; equal("main.disposition", "Partial")?;
                equal("main.oldMoveEntered", "true")?; equal("main.oldMoveNative", "1,0")?;
                equal("main.registryCommitEntered", "false")?; equal("main.registryCommitted", "false")?;
                equal("main.registryNative", "-")?;
                let new = case == SelectionCase::StopNew;
                equal("main.newMoveEntered", if new { "true" } else { "false" })?;
                equal("main.newMoveNative", if new { "1,0" } else { "-" })?;
                equal("main.phaseMask", if new { "15" } else { "3" })?;
                for key in ["main.flushedRecords", "main.closedRecords"] { equal(key, if new { "4" } else { "2" })?; }
                need(value.get("main.firstFailure")? != "-" && d::recovery_id(value.get("recoveryRun")?))?;
            },
            SelectionCase::VerifyReuse => {
                readonly()?; no_moves()?; no_output()?; equal("main.disposition", "Selected")?; equal("main.firstFailure", "-")?;
            },
            _ => {
                equal("main.firstFailure", "-")?; equal("main.stage", "Closed")?;
                equal("main.registryCommitEntered", "true")?; equal("main.registryCommitted", "true")?;
                equal("main.registryNative", "1,0")?;
                let remove = case.mode() == d::Mode::RemoveSelection;
                equal("main.disposition", if remove { "LaunchEntriesRemoved" } else { "Selected" })?;
                if remove { equal("inputs", "0")?; equal("runtime", "0")?; equal("main.retainedBytes", "-")?;
                    equal("main.newMoveEntered", "false")?; equal("main.newMoveNative", "-")?;
                } else { readonly()?; equal("main.newMoveEntered", "true")?; equal("main.newMoveNative", "1,0")?; }
                need(d::recovery_id(value.get("recoveryRun")?)
                    && value.number("main.phaseMask", 127)? & 96 == 96)?;
            }
        }
    }
    need(value.get("main.charged")? == value.get("main.confirmed")?
        && value.number("main.phaseMask", 127)? == expected_phase_mask(case))?;
    if expected_phase_mask(case) != 0 {
        equal("main.oldMoveEntered", if old_move(case) { "true" } else { "false" })?;
        equal("main.oldMoveNative", if old_move(case) { "1,0" } else { "-" })?;
    }
    validate_rename_routes(value)
}
fn validate_rename_routes(value: &SelectionAccounting) -> Result<()> {
    let root = format!("selection/recovery/{}", value.get("recoveryRun")?);
    let mut expected = Vec::new();
    if value.get("main.oldMoveEntered")? == "true" {
        expected.push(("selector".to_owned(), format!("{root}/previous.lnk")));
    }
    if value.get("main.newMoveEntered")? == "true" {
        expected.push((format!("{root}/incoming.lnk"), "selector".to_owned()));
    }
    let actual: Vec<_> = value.outputs.iter().filter(|o| o.kind == d::OutputKind::Rename)
        .map(|o| (o.path.clone(), o.destination.clone().unwrap_or_default())).collect();
    // Exactly the two possible reported operations, in returned order. No
    // extra rename cycle may disappear behind an unchanged final name census.
    need(actual == expected)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Tree {
    role: String, directories: usize, files: usize, bytes: u64, commitment: String,
}
impl Tree {
    fn line(&self) -> String {
        format!("tree={}|{}|{}|{}|{}\n", self.role, self.directories, self.files, self.bytes, self.commitment)
    }
}
fn complete_tree_bytes(role: &str, mut objects: Vec<ObservedObject>) -> Result<(usize, usize, u64, Vec<u8>)> {
    need(matches!(role, "runtime") || SOURCES.iter().any(|c|
        role == format!("source/{}", c.label()) || role == format!("image/{}", c.label())))?;
    objects.sort_by(|a, b| a.role.cmp(&b.role));
    need(!objects.is_empty() && objects.len() <= 66)?;
    let mut names = BTreeSet::new(); let mut identities = BTreeSet::new();
    let mut raw = format!("MRK_WINDOWS_SELECTION_COMPLETE_TREE_V1\0{role}\0{}", objects.len()).into_bytes();
    raw.push(0);
    let (mut directories, mut files, mut bytes) = (0, 0, 0u64);
    for object in &objects {
        need(!object.role.is_empty() && object.role.len() <= 512 && !object.role.contains(['|', '\n', '\r', '\0'])
            && names.insert(&object.role) && identities.insert((object.stamp.volume, object.stamp.id)))?;
        need(object.stamp.size >= 0 && object.stamp.allocation >= object.stamp.size
            && (object.stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0) == object.directory
            && is_hex(&object.security, 64)
            && if object.directory { object.sha == "-" && is_hex(&object.inventory, 64) }
                else { is_hex(&object.sha, 64) && object.inventory == "-" })?;
        if object.directory { directories += 1; } else { files += 1; bytes = bytes.checked_add(object.stamp.size as u64).ok_or(Error::Bounds)?; }
        // Every path, kind, full-nine stamp, ACL, content digest and exact child
        // roster is in the domain-separated commitment. No metadata stripping.
        raw.extend(object.line().as_bytes());
    }
    let expected = if role == "runtime" { (2, 47) }
        else if role.starts_with("source/") { (9, 54) } else { (IMAGE_DIRECTORIES, 54) };
    need((directories, files) == expected)?;
    Ok((directories, files, bytes, raw))
}
fn tree_commitment(role: &str, objects: Vec<ObservedObject>) -> Result<Tree> {
    let (directories, files, bytes, raw) = complete_tree_bytes(role, objects)?;
    Ok(Tree { role: role.to_owned(), directories, files, bytes, commitment: digest(&raw)? })
}
fn source_tree(input: &Inputs, objects: Vec<ObservedObject>) -> Result<Tree> {
    let layout = input.layout()?;
    let mut mapped = Vec::new();
    for mut object in objects {
        let (prefix, index) = object.role.rsplit_once('/').ok_or(Error::Unsafe)?;
        let index = number(index, 54)? as usize;
        object.role = if prefix == "s/f" { layout.paths.get(index).ok_or(Error::Unsafe)?.source.clone() }
            else if prefix == "s/d" { let path = layout.source_directories.get(index).ok_or(Error::Unsafe)?;
                if path.is_empty() { ".".to_owned() } else { path.clone() } }
            else { return Err(Error::Unsafe); };
        mapped.push(object);
    }
    tree_commitment(&format!("source/{}", input.case().label()), mapped)
}
fn image_tree(input: &Inputs, objects: Vec<ObservedObject>) -> Result<Tree> {
    let layout = input.layout()?;
    let dirs: Vec<_> = layout.output_directories.iter().filter(|p| own_dir(input, p)).collect();
    need(dirs.len() == IMAGE_DIRECTORIES)?;
    let mut mapped = Vec::new();
    for mut object in objects {
        let (prefix, index) = object.role.rsplit_once('/').ok_or(Error::Unsafe)?;
        let index = number(index, 54)? as usize;
        object.role = if prefix == format!("i{}/f", input.case().index()) { layout.paths.get(index).ok_or(Error::Unsafe)?.output.clone() }
            else if prefix == format!("i{}/d", input.case().index()) { (*dirs.get(index).ok_or(Error::Unsafe)?).clone() }
            else { return Err(Error::Unsafe); };
        mapped.push(object);
    }
    tree_commitment(&format!("image/{}", input.case().label()), mapped)
}
fn runtime_tree(input: &Inputs, objects: Vec<ObservedObject>) -> Result<Tree> {
    let version = format!("versions/{TARGET}/{}", input.manifest);
    let mut mapped = Vec::new();
    for mut object in objects {
        let (prefix, index) = object.role.rsplit_once('/').ok_or(Error::Unsafe)?;
        let index = number(index, 47)? as usize;
        object.role = if prefix == "d/f" { format!("{version}/{}", PAYLOAD_NAMES.get(index).ok_or(Error::Unsafe)?) }
            else if prefix == "d/d" { match index { 0 => version.clone(), 1 => format!("{version}/python"), _ => return Err(Error::Unsafe) } }
            else { return Err(Error::Unsafe); };
        mapped.push(object);
    }
    tree_commitment("runtime", mapped)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Origin { directory: bool, case: String, path: String }
#[derive(Clone)]
struct Run {
    case: SelectionCase, accounting: SelectionAccounting,
    old_origin: Option<Origin>, new_origin: Option<Origin>,
    old_image: Option<Case>, old_registry: Option<Case>, new_image: Option<Case>,
}
struct Episode {
    apps: Vec<(SelectionCase, SelectionAccounting)>,
    runs: Vec<Run>, objects: BTreeMap<String, Origin>,
    sources: Vec<Case>, images: Vec<Case>, selector: Option<Case>,
    registration: Option<Case>, foreign: bool,
}
fn chosen(case: SelectionCase) -> Option<Case> { match case {
    SelectionCase::SelectFresh => Some(Case::Fresh),
    SelectionCase::SelectReuse | SelectionCase::RepairReuse | SelectionCase::RecoverPrevious => Some(Case::Reuse),
    SelectionCase::StopOld => Some(Case::WrongCaller),
    SelectionCase::StopNew | SelectionCase::RecoverCurrent => Some(Case::BadManifest),
    _ => None,
} }
fn apply_state(case: SelectionCase, selector: &mut Option<Case>, registration: &mut Option<Case>) {
    match case {
        SelectionCase::SelectFresh | SelectionCase::SelectReuse | SelectionCase::RepairReuse
            | SelectionCase::RecoverPrevious | SelectionCase::RecoverCurrent => {
                *selector = chosen(case); *registration = *selector;
            },
        SelectionCase::RemoveReuse | SelectionCase::RemoveDamaged => { *selector = None; *registration = None; },
        SelectionCase::StopOld => *selector = None,
        SelectionCase::StopNew => *selector = Some(Case::BadManifest),
        _ => {},
    }
}
impl Episode {
    fn new(role: &str, apps: Vec<(SelectionCase, SelectionAccounting)>) -> Result<Self> {
        let position = role_position(role)?;
        let prefix = &SELECTION_EPISODE_ROLES[..=position];
        let expected: Vec<_> = prefix.iter().filter_map(|r| role_case(r)).collect();
        need(expected == apps.iter().map(|(c, _)| *c).collect::<Vec<_>>())?;
        let sources: Vec<_> = SOURCES.into_iter().filter(|c| prefix.contains(&source_stage(*c))).collect();
        let images: Vec<_> = SOURCES.into_iter().filter(|c| expected.contains(&source_selection(*c))).collect();
        let mut result = Self { apps, runs: Vec::new(), objects: BTreeMap::new(), sources, images,
            selector: None, registration: None, foreign: prefix.contains(&"stage-owned-foreign-selector") };
        for (case, accounting) in &result.apps {
            let old_origin = result.objects.get("selector").cloned();
            let mut new_origin = None;
            for output in &accounting.outputs {
                need(output.native_return == (1, 0))?;
                match output.kind {
                    d::OutputKind::CreatedDirectory | d::OutputKind::CreatedFile => {
                        let directory = output.kind == d::OutputKind::CreatedDirectory;
                        let origin = Origin { directory, case: case.label().to_owned(), path: output.path.clone() };
                        need(result.objects.insert(output.path.clone(), origin.clone()).is_none())?;
                        if output.path.ends_with("/incoming.lnk") { need(new_origin.replace(origin).is_none())?; }
                    },
                    d::OutputKind::Rename => {
                        let destination = output.destination.as_ref().ok_or(Error::Unsafe)?;
                        let origin = result.objects.remove(&output.path).ok_or(Error::Unsafe)?;
                        need(!origin.directory && result.objects.insert(destination.clone(), origin).is_none())?;
                    },
                }
            }
            if accounting.get("recoveryRun")? != "-" {
                need(result.runs.len() < MAX_RUNS)?;
                result.runs.push(Run { case: *case, accounting: accounting.clone(), old_origin, new_origin,
                    old_image: result.selector, old_registry: result.registration, new_image: chosen(*case) });
            }
            apply_state(*case, &mut result.selector, &mut result.registration);
        }
        if result.foreign {
            need(result.selector.is_none() && result.registration.is_none()
                && result.objects.insert("selector".to_owned(), Origin { directory: false,
                    case: "stage-owned-foreign-selector".to_owned(), path: "selector".to_owned() }).is_none())?;
        }
        let mut expected = BTreeSet::new();
        if !result.images.is_empty() {
            expected.extend(["selection".to_owned(), format!("selection/{TARGET}"), "selection/recovery".to_owned()]);
            for case in &result.images {
                let input = installer_fixture_inputs(*case)?;
                let root = format!("selection/{TARGET}/{}", input.image);
                expected.extend([root.clone(), format!("{root}/profile.json"), format!("{root}/launch.lnk")]);
            }
            for run in &result.runs {
                let root = format!("selection/recovery/{}", run.accounting.get("recoveryRun")?);
                expected.insert(root.clone());
                let mask = run.accounting.number("main.phaseMask", 127)?;
                for i in 0..d::PHASES.len() { if mask & (1 << i) != 0 { expected.insert(format!("{root}/record-{i:02}.bin")); } }
                if run.accounting.get("main.oldMoveEntered")? == "true" { expected.insert(format!("{root}/previous.lnk")); }
                if run.new_origin.is_some() && run.accounting.get("main.newMoveEntered")? == "false" {
                    expected.insert(format!("{root}/incoming.lnk"));
                }
            }
        }
        if result.selector.is_some() || result.foreign { expected.insert("selector".to_owned()); }
        need(result.objects.keys().cloned().collect::<BTreeSet<_>>() == expected)?;
        Ok(result)
    }
    fn final_path(&self, origin: &Origin) -> Result<&str> {
        let mut found = self.objects.iter().filter(|(_, candidate)| *candidate == origin);
        let path = found.next().ok_or(Error::Unsafe)?.0;
        need(found.next().is_none())?; Ok(path)
    }
}
#[derive(Clone, Debug)]
struct Snapshot { record: Wire, trees: Vec<Tree>, objects: Vec<ObservedObject> }
fn damage_field(object: &ObservedObject) -> Result<String> {
    need(!object.directory && object.role == object_role(Case::BadManifest, false, 48))?;
    Ok(format!("{}|{}|{}", stamp_text(&object.stamp), object.security, object.sha))
}
fn damage_object(value: &str) -> Result<Option<ObservedObject>> {
    if value == "-" { return Ok(None); }
    let parts: Vec<_> = value.split('|').collect();
    need(parts.len() == 3 && is_hex(parts[1], 64) && is_hex(parts[2], 64))?;
    let stamp = parse_stamp(parts[0])?; need(stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY == 0)?;
    Ok(Some(ObservedObject { role: object_role(Case::BadManifest, false, 48), directory: false,
        stamp, security: parts[1].to_owned(), sha: parts[2].to_owned(), inventory: "-".to_owned() }))
}
fn parse_snapshot(raw: &[u8]) -> Result<Snapshot> {
    need(!raw.is_empty() && raw.len() <= OWNER_LIMIT && raw.is_ascii() && raw.ends_with(b"\n")
        && raw.iter().all(|b| *b == 10 || (32..=126).contains(b)))?;
    let lines: Vec<_> = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?.lines().collect();
    let head = KEYS.len() + 1; need(lines.len() >= head)?;
    let record = Wire::parse((lines[..head].join("\n") + "\n").as_bytes(), HEADER, KEYS, OWNER_LIMIT)?;
    record.equal("profile", SELECTION_FIXTURE_PROFILE)?;
    role_position(record.get("role")?)?; selection_native_test(record.get("role")?)?;
    for key in ["parentBookSettled", "selectionPrimitivesClosed"] { record.equal(key, "true")?; }
    record.equal("unknown", "false")?;
    record.equal("resultCloseGate", "original-fixture-exit-zero-required")?;
    need(record.number("fileOriginals", open_budget(record.get("role")?)? as u64)? > 0
        && record.get("fileOriginals")? == record.get("fileOriginalsClosed")?)?;
    need(d::native_dos_path(record.get("programFiles")?) && d::native_dos_path(record.get("commonPrograms")?))?;
    need(record.get("candidate")? == "-" || d::native_dos_path(record.get("candidate")?))?;
    need(matches!(record.get("freshMrkAbsent")?, "true" | "false"))?;
    for key in ["selectorImage", "registrationImage"] { need(record.get(key)? == "-" || d::digest(record.get(key)?))?; }
    need(record.get("registrationSecurityDigest")? == "-" || d::digest(record.get("registrationSecurityDigest")?))?;
    record.number("registrationWrite", u64::MAX)?;
    need(record.get("foreignSelector")? == "-" || d::digest(record.get("foreignSelector")?))?;
    damage_object(record.get("damagedShell")?)?;
    record.number("accountedRuns", MAX_RUNS as u64)?;
    let count = record.number("trees", 9)? as usize;
    let object_count = record.number("objects", MAX_OBJECTS as u64)? as usize;
    need(lines.len() == head + count + object_count)?;
    let mut trees = Vec::new(); let mut last = String::new();
    for line in &lines[head..head+count] {
        let row: Vec<_> = line.strip_prefix("tree=").ok_or(Error::Unsafe)?.split('|').collect();
        need(row.len() == 5 && row[0] > last.as_str() && is_hex(row[4], 64))?;
        let expected = if row[0] == "runtime" { (2, 47) }
            else if SOURCES.iter().any(|c| row[0] == format!("source/{}", c.label())) { (9, 54) }
            else if SOURCES.iter().any(|c| row[0] == format!("image/{}", c.label())) { (IMAGE_DIRECTORIES, 54) }
            else { return Err(Error::Unsafe); };
        let directories = number(row[1], 12)? as usize; let files = number(row[2], 54)? as usize;
        need((directories, files) == expected)?;
        let bytes = number(row[3], 128 * 1024 * 1024)?;
        need(bytes > 0)?;
        trees.push(Tree { role: row[0].to_owned(), directories, files, bytes, commitment: row[4].to_owned() });
        last = row[0].to_owned();
    }
    let mut objects = Vec::new(); let mut identities = BTreeSet::new(); let mut last = String::new();
    for line in &lines[head+count..] {
        let row: Vec<_> = line.strip_prefix("observed=").ok_or(Error::Unsafe)?.split('|').collect();
        need(row.len() == 6 && row[0] > last.as_str() && row[0].len() <= 192
            && (super::super::super::installer_selection_fixture_data::selection_accounting_role(row[0])
                || matches!(row[0], "os/program-files" | "os/programs" | "shared/mrk"
                    | "shared/installer-input" | "shared/installer-target" | "shared/runtime-input"
                    | "shared/runtime-target" | "shared/versions" | "shared/versions-target"))
            && matches!(row[1], "directory" | "file") && is_hex(row[3], 64))?;
        let stamp = parse_stamp(row[2])?; let directory = row[1] == "directory";
        need((stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0) == directory
            && identities.insert((stamp.volume, stamp.id))
            && if directory { row[4] == "-" && is_hex(row[5], 64) }
                else { is_hex(row[4], 64) && row[5] == "-" })?;
        objects.push(ObservedObject { role: row[0].to_owned(), directory, stamp,
            security: row[3].to_owned(), sha: row[4].to_owned(), inventory: row[5].to_owned() });
        last = row[0].to_owned();
    }
    need(objects.len() >= 2 && objects.iter().all(|o| o.stamp.volume == objects[0].stamp.volume))?;
    Ok(Snapshot { record, trees, objects })
}

impl Fixture {
    fn selection_result(&mut self, pre: &Wire, pre_raw: &[u8], role: &str) -> Result<Vec<u8>> {
        let raw = self.retained_input(&result_name(role)?, OWNER_LIMIT)?;
        let exit_raw = self.retained_input(&format!("retained-{role}-exit.private.txt"), LIMIT)?;
        let exit = Wire::parse(&exit_raw, EXIT_HEADER, EXIT_KEYS, LIMIT)?;
        exit.binding()?; exit.equal("profile", SELECTION_FIXTURE_PROFILE)?; exit.equal("role", role)?;
        let case = role_case(role);
        let artifact = if case.is_some() { "app" } else { "native" };
        let test = case.map(|c| Ok(c.app_test())).unwrap_or_else(|| selection_native_test(role))?;
        exit.equal("artifactSha256", pre.get(&format!("{artifact}ArtifactSha256"))?)?;
        exit.equal("precheckSha256", &digest(pre_raw)?)?;
        exit.equal("commandSha256", &command_sha(pre.get(&format!("{artifact}Artifact"))?, test)?)?;
        exit.equal("resultSha256", &digest(&raw)?)?;
        need(exit.number("resultBytes", OWNER_LIMIT as u64)? == raw.len() as u64)?;
        exit.equal("originalWaitReturned", "true")?; exit.equal("exitCode", "0")?;
        exit.equal("writerCloseGate", "original-owner-closed-output")?;
        Ok(raw)
    }
    fn selection_proofs(&mut self, pre: &Wire, pre_raw: &[u8], role: &str) -> Result<(Episode, Option<Snapshot>)> {
        let position = role_position(role)?;
        let mut apps = Vec::new();
        for prior in &SELECTION_EPISODE_ROLES[..position] {
            if let Some(case) = role_case(prior) {
                apps.push((case, parse_app(&self.selection_result(pre, pre_raw, prior)?, case, pre)?));
            }
        }
        let last_native = SELECTION_EPISODE_ROLES[..position].iter().rev()
            .find(|r| selection_native_test(r).is_ok());
        let previous = if let Some(prior) = last_native {
            let raw = self.selection_result(pre, pre_raw, prior)?;
            let snapshot = parse_snapshot(&raw)?;
            snapshot.record.binding()?; snapshot.record.equal("role", prior)?;
            snapshot.record.equal("precheckSha256", &digest(pre_raw)?)?;
            snapshot.record.equal("profilesSha256", pre.get("profilesSha256")?)?;
            snapshot.record.equal("rosterSha256", pre.get("rosterSha256")?)?;
            Some(snapshot)
        } else { need(role == "stage-fresh")?; None };
        Ok((Episode::new(role, apps)?, previous))
    }
}

#[derive(Clone)]
struct Leaf { object: ObservedObject, bytes: Vec<u8>, descriptor: Vec<u8> }
impl Fixture {
    fn selection_next_entries(&mut self, index: usize, selected: Option<&str>) -> Result<Vec<DirectoryEntry>> {
        let epoch = self.cursors.get(index).ok_or(Error::State)?.epoch.map_or(0, |n| n + 1);
        self.entries_at(index, selected, epoch)
    }
    fn selection_os_location(&mut self, kind: LocationKind) -> Result<(KnownLocation, usize, usize)> {
        need(matches!(kind, LocationKind::CommonPrograms | LocationKind::System))?;
        self.gate()?; let location = self.book.location(kind)?; self.gate()?;
        let pf = self.location.as_ref().ok_or(Error::State)?;
        need(pf.same_volume(&location) && Arc::ptr_eq(&self.book.identity, &location.book)
            && self.book.mapping(&location.drive)? == location.device)?;
        let root = fixed_path(&location.path)?;
        let mut paths: Vec<_> = root.ancestors().map(Path::to_path_buf).collect(); paths.reverse();
        need(!paths.is_empty() && paths.len() <= 8 && self.files.len() + paths.len() + 1 <= 40)?;
        let begin = self.files.len(); let mut indices = Vec::new();
        for path in paths {
            let index = self.directory(&path, 0, Some(AuthorityScope::AncestorOutsideVersion), None)?;
            let expected = format!("{}{}", location.device,
                path.to_str().ok_or(Error::Unsafe)?.strip_prefix(&location.drive).ok_or(Error::Unsafe)?);
            need(self.borrowed_call(index, Call::FinalName)?.text(NAME_UNITS, true)? == expected
                && self.borrowed_call(index, Call::VolumeName)?.text(261, false)? == "NTFS")?;
            let device = self.borrowed_call(index, Call::VolumeDevice)?; let raw = device.nt_bytes()?;
            need(raw.len() == size_of::<NS::FILE_FS_DEVICE_INFORMATION>()
                && decode::u32_at(raw, offset_of!(NS::FILE_FS_DEVICE_INFORMATION, DeviceType))? == FS::FILE_DEVICE_DISK
                && decode::u32_at(raw, offset_of!(NS::FILE_FS_DEVICE_INFORMATION, Characteristics))? & NS::FILE_REMOTE_DEVICE == 0)?;
            indices.push(index);
        }
        for pair in indices.windows(2) { self.parent_link(pair[0], pair[1])?; }
        let index = *indices.last().ok_or(Error::State)?;
        need(self.snapshots.get(&index).ok_or(Error::State)?.volume
            == self.snapshots.get(&(self.ancestors + self.program_files - 1)).ok_or(Error::State)?.volume)?;
        self.book.recheck_location(&location)?; self.gate()?;
        Ok((location, begin, index))
    }
    fn selection_source(&mut self, inputs: &Inputs) -> Result<Vec<ObservedObject>> {
        let layout = inputs.layout()?;
        let base = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join(inputs.source_leaf());
        let begin = self.files.len(); need(begin + 9 + 1 <= 40)?;
        let mut dirs = BTreeMap::new(); let mut leaves = BTreeMap::new(); let mut objects = Vec::new();
        for path in &layout.source_directories {
            let index = self.directory(&relative(&base, path)?, 0, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            dirs.insert(path.clone(), index);
        }
        for i in 0..INPUTS {
            let path = &layout.paths[i].source;
            let (index, bytes) = self.input(&relative(&base, path)?, PAYLOAD_LIMIT)?;
            let (stamp, descriptor) = self.checked(index, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            need(bytes.len() as u64 == inputs.sizes[i] && digest(&bytes)? == inputs.hashes[i])?;
            leaves.insert(path.clone(), stamp.clone());
            objects.push(ObservedObject { role: format!("s/f/{i}"), directory: false, stamp,
                security: digest(&descriptor)?, sha: inputs.hashes[i].to_owned(), inventory: "-".to_owned() });
            self.recheck(index)?; self.close(index)?; self.pop_closed(index)?;
        }
        let inventories = self.retained_tree_census(&dirs, &leaves, |_| true)?;
        for (i, path) in layout.source_directories.iter().enumerate() {
            let mut object = self.observed_directory(*dirs.get(path).ok_or(Error::State)?, &format!("s/d/{i}"))?;
            object.inventory = inventories.get(path).ok_or(Error::State)?.clone(); objects.push(object);
        }
        self.retained_close_from(begin)?;
        Ok(objects)
    }
    fn selection_branch(&mut self, role: &str, path: &Path, episode: &Episode,
        objects: &mut Vec<ObservedObject>, leaves: &mut BTreeMap<String, Leaf>) -> Result<Stamp> {
        need(episode.objects.get(role).is_some_and(|o| o.directory))?;
        let index = self.directory(path, 0, Some(AuthorityScope::ImmutableVersion), None)?;
        sd(&self.descriptor(index)?, true, false, false)?;
        let mut children = BTreeMap::new();
        let entries: Vec<_> = episode.objects.iter().filter(|(name, _)| parent(name).0 == role)
            .map(|(name, origin)| (name.clone(), origin.clone())).collect();
        need(entries.len() <= 10)?;
        for (name, origin) in entries {
            let child = path.join(parent(&name).1);
            let stamp = if origin.directory {
                self.selection_branch(&name, &child, episode, objects, leaves)?
            } else {
                let (reader, bytes) = self.input(&child, d::RECORD_LIMIT)?;
                let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
                let public = name.ends_with("/incoming.lnk") || name.ends_with("/previous.lnk");
                sd(&descriptor, false, false, public)?;
                let object = ObservedObject { role: name.clone(), directory: false, stamp: stamp.clone(),
                    security: digest(&descriptor)?, sha: digest(&bytes)?, inventory: "-".to_owned() };
                need(leaves.insert(name.clone(), Leaf { object: object.clone(), bytes, descriptor }).is_none())?;
                objects.push(object);
                self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?; stamp
            };
            need(children.insert(parent(&name).1.to_owned(), stamp).is_none())?;
        }
        let rows = self.entries(index, None)?;
        let own = self.snapshots.get(&index).ok_or(Error::State)?.clone();
        let parent_stamp = self.paths.iter().position(|p| Some(p.as_path()) == path.parent()).and_then(|i| self.snapshots.get(&i));
        exact_entries(&rows, &children, &own, parent_stamp)?;
        let mut object = self.observed_directory(index, role)?;
        object.inventory = inventory_sha(&children)?;
        objects.push(object);
        self.recheck(index)?; self.close(index)?; self.pop_closed(index)?;
        Ok(own)
    }
    fn selection_shared(&mut self, episode: &Episode, external: &BTreeMap<String, Stamp>)
        -> Result<Vec<ObservedObject>> {
        if episode.images.is_empty() { need(external.is_empty())?; return Ok(Vec::new()); }
        let base = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit");
        let paths = [(String::new(), "shared/mrk"), ("installer-input".to_owned(), "shared/installer-input"),
            (format!("installer-input/{TARGET}"), "shared/installer-target"),
            ("runtime-input".to_owned(), "shared/runtime-input"), (format!("runtime-input/{TARGET}"), "shared/runtime-target"),
            ("versions".to_owned(), "shared/versions"), (format!("versions/{TARGET}"), "shared/versions-target")];
        let begin = self.files.len(); need(begin + paths.len() <= 40)?;
        let mut dirs = BTreeMap::new();
        for (path, _) in &paths {
            let index = self.directory(&relative(&base, path)?, 0, Some(AuthorityScope::ImmutableVersion), None)?;
            let public = path.is_empty() || path.starts_with("installer-input") || path.starts_with("versions");
            sd(&self.descriptor(index)?, true, false, public)?;
            dirs.insert(path.clone(), index);
        }
        let inventories = self.retained_tree_census(&dirs, external, |_| true)?;
        let mut result = Vec::new();
        for (path, role) in paths {
            let mut object = self.observed_directory(*dirs.get(&path).ok_or(Error::State)?, role)?;
            object.inventory = inventories.get(&path).ok_or(Error::State)?.clone(); result.push(object);
        }
        self.retained_close_from(begin)?; Ok(result)
    }
    fn selection_damage(&mut self, previous: &Snapshot) -> Result<(ObservedObject, Tree)> {
        let input = installer_fixture_inputs(Case::BadManifest)?;
        need(previous.record.get("role")? == "recover-current-observe" && previous.record.get("damagedShell")? == "-")?;
        let mut before_objects = self.retained_image(&input, true, None)?;
        let before_tree = image_tree(&input, before_objects.clone())?;
        need(previous.trees.iter().find(|t| t.role == before_tree.role) == Some(&before_tree))?;
        let expected = before_objects.iter().find(|o| o.role == object_role(Case::BadManifest, false, 48))
            .ok_or(Error::Unsafe)?.clone();
        let path = relative(&Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit"),
            &input.layout()?.paths[48].output)?;
        let (reader, mut bytes) = self.input(&path, PAYLOAD_LIMIT)?;
        let (before, before_sd) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
        sd(&before_sd, false, true, true)?;
        need(before == expected.stamp && digest(&before_sd)? == expected.security && !bytes.is_empty()
            && bytes.len() as u64 == input.sizes[48] && digest(&bytes)? == input.hashes[48])?;
        self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        bytes[0] ^= 1; // one fixed same-length task-owned payload mutation
        let writer = self.open(&path, false, FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE)?;
        let (opened, opened_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), None)?;
        need(opened == before && opened_sd == before_sd)?;
        self.files[writer].write_fixture_payload(&bytes)?; self.gate()?;
        let (written, written_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), None)?;
        need(same_object(&opened, &written) && written.size == opened.size && written.allocation == opened.allocation
            && written.write >= opened.write && written.change >= opened.change && written_sd == opened_sd)?;
        self.close(writer)?; self.pop_closed(writer)?;
        let (reader, actual) = self.input(&path, PAYLOAD_LIMIT)?;
        let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
        need(stamp == written && descriptor == written_sd && actual == bytes && digest(&actual)? != input.hashes[48])?;
        let object = ObservedObject { role: object_role(Case::BadManifest, false, 48), directory: false,
            stamp, security: digest(&descriptor)?, sha: digest(&actual)?, inventory: "-".to_owned() };
        self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        let at = before_objects.iter().position(|o| o.role == object.role).ok_or(Error::State)?;
        before_objects[at] = object.clone();
        Ok((object, image_tree(&input, before_objects)?))
    }
    fn selection_foreign(&mut self, previous: &Snapshot, observer: &mut Observer) -> Result<String> {
        need(previous.record.get("role")? == "remove-damaged-observe"
            && previous.record.get("selectorImage")? == "-" && previous.record.get("registrationImage")? == "-"
            && previous.record.get("foreignSelector")? == "-")?;
        let (location, begin, programs) = self.selection_os_location(LocationKind::CommonPrograms)?;
        self.absent(programs, d::SHORTCUT)?;
        let pf = self.location.as_ref().ok_or(Error::State)?.path.clone();
        let bytes = observer.encode_foreign_once(&Boundary { original: RefCell::new(&mut *self) }, &pf)?;
        let path = Path::new(&location.path).join(d::SHORTCUT);
        self.recheck(programs)?;
        let writer = self.create_file(&path)?; self.update_parent(programs)?;
        let (empty, empty_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), Some(false))?;
        need(empty.size == 0)?;
        self.files[writer].write_fixture_payload(&bytes)?; self.gate()?;
        let (written, written_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), Some(false))?;
        need(payload_change(&empty, &written, bytes.len()) && empty_sd == written_sd)?;
        let (sealed, sealed_sd) = self.seal(writer)?;
        sd(&sealed_sd, false, false, true)?;
        need(acl_stamp(&written, &sealed))?;
        self.close(writer)?; self.pop_closed(writer)?;
        let (reader, actual) = self.input(&path, d::LINK_LIMIT)?;
        let (readback, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), Some(true))?;
        need(readback == sealed && descriptor == sealed_sd && actual == bytes)?;
        self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        let rows = self.selection_next_entries(programs, Some(d::SHORTCUT))?;
        let selected: Vec<_> = rows.iter().filter(|r| r.name.eq_ignore_ascii_case(d::SHORTCUT)).collect();
        need(selected.len() == 1 && selected[0].name == d::SHORTCUT && selected[0].kind == FileKind::File
            && selected[0].file_id == readback.id && selected[0].attributes == readback.attributes)?;
        self.recheck(programs)?; self.book.recheck_location(&location)?; self.gate()?;
        self.retained_close_from(begin)?;
        digest(&bytes)
    }
}

fn collect_unique(objects: &[ObservedObject], identities: &mut BTreeSet<(u64, [u8; 16])>) -> Result<()> {
    for object in objects { need(identities.insert((object.stamp.volume, object.stamp.id)))?; }
    Ok(())
}
fn observed_image(case: Option<Case>) -> Result<String> {
    case.map(|c| installer_fixture_inputs(c).map(|input| input.image.to_owned()))
        .transpose().map(|v| v.unwrap_or_else(|| "-".to_owned()))
}
fn registry_for(program_files: &str, case: Option<Case>) -> Result<d::Registration> {
    if let Some(case) = case {
        d::registration(program_files, &image_data(&installer_fixture_inputs(case)?)).ok_or(Error::Unsafe)
    } else { Ok(d::Registration::new()) }
}
fn expected_phase_mask(case: SelectionCase) -> u64 { match case {
    SelectionCase::SelectFresh | SelectionCase::RepairReuse | SelectionCase::RecoverPrevious => 121,
    SelectionCase::SelectReuse | SelectionCase::RecoverCurrent => 127,
    SelectionCase::RemoveReuse | SelectionCase::RemoveDamaged => 103,
    SelectionCase::StopOld => 3, SelectionCase::StopNew => 15, _ => 0,
} }
fn previous_returns(phase: usize, old: bool, new: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for present in [old && phase >= 2, new && phase >= 4] {
        if present { bytes.extend([1, 7]); bytes.extend(1i32.to_le_bytes()); bytes.extend(0u32.to_le_bytes()); }
    }
    if phase >= 6 { bytes.extend([2, 19, 1]); bytes.extend(1i64.to_le_bytes()); bytes.extend(0u32.to_le_bytes()); }
    bytes
}
fn actual_path(program_files: &str, common_programs: &str, role: &str) -> Result<String> {
    if role == "selector" { return Ok(format!(r"{common_programs}\{}", d::SHORTCUT)); }
    need(super::super::super::installer_selection_fixture_data::selection_accounting_role(role))?;
    Ok(format!(r"{program_files}\Mobile Release Kit\{}", role.replace('/', "\\")))
}
fn validate_runs(episode: &Episode, leaves: &BTreeMap<String, Leaf>,
    canonical: &BTreeMap<String, Vec<u8>>, program_files: &str, common_programs: &str,
    previous: Option<&Snapshot>, registration: &RegistrationObservation) -> Result<()> {
    for run in &episode.runs {
        let account = &run.accounting;
        let id = account.get("recoveryRun")?;
        let root = format!("selection/recovery/{id}");
        let mask = account.number("main.phaseMask", 127)?;
        need(mask == expected_phase_mask(run.case))?;
        let old = run.old_image.map(|c| installer_fixture_inputs(c).map(|v| v.image.to_owned())).transpose()?;
        let new = run.new_image.map(|c| installer_fixture_inputs(c).map(|v| v.image.to_owned())).transpose()?;
        let before_image = run.old_image.or(run.old_registry).map(|c| installer_fixture_inputs(c)
            .map(|v| v.image.to_owned())).transpose()?;
        let expected_image = new.clone().or(before_image.clone()).ok_or(Error::Unsafe)?;
        let old_bytes = old.as_ref().map(|i| canonical.get(i).map(Vec::as_slice).ok_or(Error::Unsafe))
            .transpose()?.unwrap_or(&[]);
        let new_bytes = new.as_ref().map(|i| canonical.get(i).map(Vec::as_slice).ok_or(Error::Unsafe))
            .transpose()?.unwrap_or(&[]);
        let old_registry = registry_for(program_files, run.old_registry)?;
        let new_registry = registry_for(program_files, run.new_image)?;
        for ordinal in 0..d::PHASES.len() {
            let name = format!("{root}/record-{ordinal:02}.bin");
            if mask & (1 << ordinal) == 0 { need(!leaves.contains_key(&name))?; continue; }
            let raw = &leaves.get(&name).ok_or(Error::Unsafe)?.bytes;
            let record = d::RecoveryRecord::decode(raw).ok_or(Error::Unsafe)?;
            need(record.mode == run.case.mode() && record.phase == d::PHASES[ordinal] && record.run == id
                && record.image == expected_image && record.before_image == before_image
                && record.observation == account.get("previewObservationSha256")?
                && record.old_link == old_bytes && record.new_link == new_bytes
                && record.old_registry == old_registry && record.new_registry == new_registry
                && record.prior_returns == previous_returns(ordinal,
                    account.get("main.oldMoveEntered")? == "true", account.get("main.newMoveEntered")? == "true"))?;
            for (values, raw_sd) in [(&old_registry, &record.old_registry_security), (&new_registry, &record.new_registry_security)] {
                if values.is_empty() { need(raw_sd.is_empty())?; }
                else { security::Observed::new(Refusal::none()).selection_descriptor(raw_sd, security::SelectionDescriptor::Registration)?; }
            }
            if let Some(previous) = previous.filter(|s| role_position(run.case.label()).is_ok_and(|at|
                role_position(s.record.get("role").unwrap_or("")).is_ok_and(|before| at > before))) {
                // First observation of this run: bind original old/staged key
                // descriptors to actual adjacent native snapshots. Later roles
                // retain every record's full byte/identity commitment unchanged.
                if !old_registry.is_empty() {
                    need(digest(&record.old_registry_security)?
                        == previous.record.get("registrationSecurityDigest")?)?;
                }
                if !new_registry.is_empty() {
                    let expected = if account.get("main.registryCommitted")? == "true" {
                        need(registration.present)?; digest(&registration.security)?
                    } else {
                        need(!old_registry.is_empty())?;
                        previous.record.get("registrationSecurityDigest")?.to_owned()
                    };
                    need(digest(&record.new_registry_security)? == expected)?;
                }
            }
            for (origin, encoded, original_role) in [
                (run.old_origin.as_ref(), &record.old_file_descriptor, "selector".to_owned()),
                (run.new_origin.as_ref(), &record.new_file_descriptor, format!("{root}/incoming.lnk")),
            ] {
                if let Some(origin) = origin {
                    let now = episode.final_path(origin)?;
                    let observed = leaves.get(now).ok_or(Error::Unsafe)?;
                    let path = actual_path(program_files, common_programs, &original_role)?;
                    primitives::original_matches(encoded, &path, &observed.object.stamp,
                        &observed.descriptor, now != original_role)?;
                } else { need(encoded.is_empty())?; }
            }
        }
        // Prove every actual created byte still has a charged final location,
        // including incoming links subsequently renamed twice. A disposition is
        // not the persisted-output inventory.
        let mut charged = 0u64;
        for output in &account.outputs {
            if output.kind == d::OutputKind::CreatedFile {
                let origin = Origin { directory: false, case: run.case.label().to_owned(), path: output.path.clone() };
                let final_path = episode.final_path(&origin)?;
                charged = charged.checked_add(leaves.get(final_path).ok_or(Error::Unsafe)?.bytes.len() as u64).ok_or(Error::Bounds)?;
            }
        }
        charged = charged.checked_add(new_registry.values().map(|v| v.bytes.len() as u64).sum::<u64>()).ok_or(Error::Bounds)?;
        need(charged == account.number("main.charged", d::OUTPUT_LIMIT)?
            && charged == account.number("main.confirmed", d::OUTPUT_LIMIT)?)?;
        if run.case == SelectionCase::RegistryConflict {
            let staged = old_registry.values().map(|v| v.bytes.len() as u64).sum::<u64>();
            need(staged > 0 && staged == account.number("competitor.charged", d::OUTPUT_LIMIT)?
                && staged == account.number("competitor.confirmed", d::OUTPUT_LIMIT)?
                && account.competitor_outputs.is_empty())?;
        }
    }
    Ok(())
}
impl Fixture {
    fn selection_snapshot(&mut self, pre: &Wire, pre_raw: &[u8], role: &str, episode: &Episode,
        observer: &mut Observer, registration: &RegistrationObservation, pf: usize,
        staged: Option<(Case, Vec<ObservedObject>)>, damaged: Option<&ObservedObject>,
        foreign: Option<&str>, previous: Option<&Snapshot>) -> Result<Snapshot> {
        let program_files = self.location.as_ref().ok_or(Error::State)?.path.clone();
        let mut trees = Vec::new(); let mut objects = Vec::new(); let mut leaves = BTreeMap::new();
        let mut identities = BTreeSet::new(); let mut pf_children = BTreeMap::new();
        let mut external = BTreeMap::new(); let mut staged = staged;
        for case in &episode.sources {
            let input = installer_fixture_inputs(*case)?;
            let current = if staged.as_ref().is_some_and(|(current, _)| current == case) {
                staged.take().ok_or(Error::State)?.1
            } else { self.selection_source(&input)? };
            collect_unique(&current, &mut identities)?;
            let root = current.iter().find(|v| v.role == "s/d/0").ok_or(Error::Unsafe)?;
            pf_children.insert(input.source_leaf(), root.stamp.clone());
            trees.push(source_tree(&input, current)?);
        }
        need(staged.is_none())?;
        for case in &episode.images {
            let input = installer_fixture_inputs(*case)?;
            let current = self.retained_image_checked(&input, true, None,
                if *case == Case::BadManifest { damaged } else { None })?;
            collect_unique(&current, &mut identities)?;
            let layout = input.layout()?;
            let dirs: Vec<_> = layout.output_directories.iter().filter(|p| own_dir(&input, p)).collect();
            for (i, path) in dirs.iter().enumerate() {
                if *path == &format!("installer-input/{TARGET}/{}", input.image)
                    || *path == &format!("runtime-input/{TARGET}/{}", input.image) {
                    let root = current.iter().find(|v| v.role == object_role(*case, true, i)).ok_or(Error::Unsafe)?;
                    external.insert((*path).clone(), root.stamp.clone());
                }
            }
            trees.push(image_tree(&input, current)?);
        }
        if !episode.images.is_empty() {
            let input = installer_fixture_inputs(Case::Fresh)?;
            let current = self.retained_public(&input)?;
            collect_unique(&current, &mut identities)?;
            let root = current.iter().find(|v| v.role == public_role(true, 0)).ok_or(Error::Unsafe)?;
            external.insert(format!("versions/{TARGET}/{}", input.manifest), root.stamp.clone());
            trees.push(runtime_tree(&input, current)?);
            let root = Path::new(&program_files).join("Mobile Release Kit").join("selection");
            let stamp = self.selection_branch("selection", &root, episode, &mut objects, &mut leaves)?;
            external.insert("selection".to_owned(), stamp);
        }
        let mut canonical = BTreeMap::new();
        for case in &episode.images {
            let input = installer_fixture_inputs(*case)?;
            let root = format!("selection/{TARGET}/{}", input.image);
            need(leaves.get(&format!("{root}/profile.json")).is_some_and(|leaf| leaf.bytes == input.profile))?;
            let launch = &leaves.get(&format!("{root}/launch.lnk")).ok_or(Error::Unsafe)?.bytes;
            need(!launch.is_empty() && launch.len() <= d::LINK_LIMIT)?;
            observer.decode_profile(&Boundary { original: RefCell::new(&mut *self) }, launch, &program_files, input.image)?;
            canonical.insert(input.image.to_owned(), launch.clone());
        }
        objects.extend(self.selection_shared(episode, &external)?);
        if !episode.images.is_empty() {
            pf_children.insert("Mobile Release Kit".to_owned(),
                objects.iter().find(|o| o.role == "shared/mrk").ok_or(Error::Unsafe)?.stamp.clone());
        }
        self.recheck(pf)?;
        let rows = self.selection_next_entries(pf, None)?;
        for case in Case::ALL {
            let input = installer_fixture_inputs(case)?;
            let matches: Vec<_> = rows.iter().filter(|r| r.name.eq_ignore_ascii_case(&input.source_leaf())).collect();
            if let Some(expected) = pf_children.get(&input.source_leaf()) {
                need(matches.len() == 1 && matches[0].name == input.source_leaf() && matches[0].kind == FileKind::Directory
                    && matches[0].file_id == expected.id && matches[0].attributes == expected.attributes)?;
            } else { need(matches.is_empty())?; }
        }
        let matches: Vec<_> = rows.iter().filter(|r| r.name.eq_ignore_ascii_case("Mobile Release Kit")).collect();
        if let Some(expected) = pf_children.get("Mobile Release Kit") {
            need(matches.len() == 1 && matches[0].name == "Mobile Release Kit" && matches[0].kind == FileKind::Directory
                && matches[0].file_id == expected.id && matches[0].attributes == expected.attributes)?;
        } else { need(matches.is_empty())?; }
        let mut pf_object = self.observed_directory(pf, "os/program-files")?;
        pf_object.inventory = inventory_sha(&pf_children)?; objects.push(pf_object);
        let (programs_location, begin, programs) = self.selection_os_location(LocationKind::CommonPrograms)?;
        let common_programs = programs_location.path.clone();
        let rows = self.entries(programs, Some(d::SHORTCUT))?;
        let found: Vec<_> = rows.iter().filter(|r| r.name.eq_ignore_ascii_case(d::SHORTCUT)).collect();
        let mut programs_children = BTreeMap::new();
        if episode.selector.is_some() || episode.foreign {
            need(found.len() == 1 && found[0].name == d::SHORTCUT && found[0].kind == FileKind::File)?;
            let path = Path::new(&common_programs).join(d::SHORTCUT);
            let (reader, bytes) = self.input(&path, d::LINK_LIMIT)?;
            let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
            sd(&descriptor, false, false, true)?;
            need(stamp.id == found[0].file_id && stamp.attributes == found[0].attributes)?;
            let image = if episode.foreign { FOREIGN_IMAGE.to_owned() } else { observed_image(episode.selector)? };
            observer.decode_profile(&Boundary { original: RefCell::new(&mut *self) }, &bytes, &program_files, &image)?;
            if episode.foreign { need(foreign == Some(digest(&bytes)?.as_str()) && !canonical.contains_key(&image))?; }
            else { need(canonical.get(&image) == Some(&bytes) && foreign.is_none())?; }
            let object = ObservedObject { role: "selector".to_owned(), directory: false,
                stamp: stamp.clone(), security: digest(&descriptor)?, sha: digest(&bytes)?, inventory: "-".to_owned() };
            programs_children.insert(d::SHORTCUT.to_owned(), stamp);
            need(leaves.insert("selector".to_owned(), Leaf { object: object.clone(), bytes, descriptor }).is_none())?;
            objects.push(object);
            self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        } else { need(found.is_empty() && foreign.is_none())?; }
        let mut programs_object = self.observed_directory(programs, "os/programs")?;
        programs_object.inventory = inventory_sha(&programs_children)?; objects.push(programs_object);
        self.book.recheck_location(&programs_location)?; self.gate()?;
        self.retained_close_from(begin)?;
        need(registration.present == episode.registration.is_some()
            && registration.values == registry_for(&program_files, episode.registration)?
            && (registration.present || (registration.security.is_empty() && registration.write == 0)))?;
        validate_runs(episode, &leaves, &canonical, &program_files, &common_programs, previous, registration)?;
        for (name, origin) in &episode.objects {
            let object = objects.iter().find(|o| &o.role == name).ok_or(Error::Unsafe)?;
            need(object.directory == origin.directory)?;
        }
        need(objects.iter().filter(|o| !o.role.starts_with("shared/") && !o.role.starts_with("os/")).count() == episode.objects.len())?;
        collect_unique(&objects, &mut identities)?;
        trees.sort_by(|a, b| a.role.cmp(&b.role)); objects.sort_by(|a, b| a.role.cmp(&b.role));
        let mut record = Wire { values: BTreeMap::new() };
        record.copy(pre, &["profile", "sourceSha", "sourceTree", "runId", "attempt", "profilesSha256", "rosterSha256"])?;
        record.put("role", role); record.put("precheckSha256", digest(pre_raw)?);
        record.put("programFiles", &program_files); record.put("commonPrograms", common_programs);
        let staged_case = SOURCES.into_iter().find(|c| role == source_stage(*c));
        record.put("candidate", staged_case.map(|case| installer_fixture_inputs(case)
            .map(|input| format!(r"{program_files}\{}", input.source_leaf()))).transpose()?.unwrap_or_else(|| "-".to_owned()));
        record.put("freshMrkAbsent", episode.images.is_empty());
        record.put("selectorImage", if episode.foreign { FOREIGN_IMAGE.to_owned() } else { observed_image(episode.selector)? });
        record.put("registrationImage", observed_image(episode.registration)?);
        record.put("registrationSha256", &registration.complete_sha256);
        record.put("registrationSecurityDigest", if registration.present { digest(&registration.security)? } else { "-".to_owned() });
        record.put("registrationParentSha256", digest(&registration.parent_security)?);
        record.put("registrationWrite", registration.write);
        record.put("trees", trees.len()); record.put("objects", objects.len());
        record.put("damagedShell", damaged.map(damage_field).transpose()?.unwrap_or_else(|| "-".to_owned()));
        record.put("foreignSelector", foreign.unwrap_or("-")); record.put("accountedRuns", episode.runs.len());
        // Finality fields are appended ONLY after the actual owners settle.
        Ok(Snapshot { record, trees, objects })
    }
}

fn directory_transition(before: &ObservedObject, after: &ObservedObject, changed_children: bool) -> Result<()> {
    need(before.directory && after.directory && before.role == after.role)?;
    if changed_children {
        need(before.inventory != after.inventory && child_change(&before.stamp, &after.stamp)
            && before.security == after.security && before.sha == "-" && after.sha == "-")
    } else { need(before == after) }
}
fn check_transition(previous: Option<&Snapshot>, current: &Snapshot, episode: &Episode,
    role: &str, damage_tree: Option<&Tree>) -> Result<()> {
    let Some(previous) = previous else {
        need(role == "stage-fresh" && current.trees.len() == 1 && current.trees[0].role == "source/fresh"
            && current.objects.len() == 2 && current.record.get("selectorImage")? == "-"
            && current.record.get("registrationImage")? == "-")?;
        return Ok(());
    };
    let before_position = role_position(previous.record.get("role")?)?;
    let before_apps = episode.apps.iter().filter(|(case, _)| role_position(case.label()).is_ok_and(|n| n <= before_position))
        .cloned().collect();
    let before = Episode::new(previous.record.get("role")?, before_apps)?;
    for key in ["programFiles", "commonPrograms", "registrationParentSha256"] {
        need(previous.record.get(key)? == current.record.get(key)?)?;
    }
    let mut expected_new = BTreeSet::new();
    if let Some(case) = SOURCES.into_iter().find(|c| role == source_stage(*c)) {
        expected_new.insert(format!("source/{}", case.label()));
    }
    if let Some(case) = SOURCES.into_iter().find(|c| role == format!("{}-observe", source_selection(*c).label())) {
        expected_new.insert(format!("image/{}", case.label()));
        if case == Case::Fresh { expected_new.insert("runtime".to_owned()); }
    }
    for tree in &previous.trees {
        let now = current.trees.iter().find(|t| t.role == tree.role).ok_or(Error::Unsafe)?;
        if role == "damage-owned-shell" && tree.role == "image/bad-manifest" {
            need(damage_tree == Some(now) && now != tree)?;
        } else { need(now == tree)?; }
    }
    let actual_new: BTreeSet<_> = current.trees.iter().filter(|t| !previous.trees.iter().any(|b| b.role == t.role))
        .map(|t| t.role.clone()).collect();
    need(actual_new == expected_new)?;
    let old_object = |name: &str| previous.objects.iter().find(|o| o.role == name).ok_or(Error::Unsafe);
    for object in &current.objects {
        if let Some(origin) = episode.objects.get(&object.role) {
            if let Ok(old_path) = before.final_path(origin) {
                let earlier = old_object(old_path)?;
                if object.directory {
                    let child_origins = |e: &Episode, at: &str| e.objects.iter().filter(|(p, _)| parent(p).0 == at)
                        .map(|(p, o)| (parent(p).1.to_owned(), o.clone())).collect::<BTreeMap<_, _>>();
                    directory_transition(earlier, object,
                        child_origins(&before, old_path) != child_origins(episode, &object.role))?;
                } else if old_path == object.role {
                    need(earlier == object)?;
                } else {
                    let mut expected = earlier.stamp.clone(); expected.change = object.stamp.change;
                    need(!earlier.directory && expected == object.stamp && object.stamp.change >= earlier.stamp.change
                        && earlier.security == object.security && earlier.sha == object.sha
                        && earlier.inventory == "-" && object.inventory == "-")?;
                }
            } else {
                need(!previous.objects.iter().any(|p| p.stamp.volume == object.stamp.volume && p.stamp.id == object.stamp.id))?;
                let case = role.strip_suffix("-observe").unwrap_or(role);
                need(origin.case == case)?;
            }
        } else if object.role.starts_with("shared/") || object.role.starts_with("os/") {
            if let Ok(earlier) = old_object(&object.role) {
                let change = match object.role.as_str() {
                    "os/program-files" => before.sources != episode.sources || before.images.is_empty() != episode.images.is_empty(),
                    "os/programs" => before.objects.get("selector") != episode.objects.get("selector"),
                    "shared/installer-target" | "shared/runtime-target" => before.images != episode.images,
                    _ => false,
                };
                directory_transition(earlier, object, change)?;
            } else {
                need(role == "select-fresh-observe" && object.role.starts_with("shared/"))?;
            }
        } else { return Err(Error::Unsafe); }
    }
    // No deletion: existing derivative originals merely change their one known
    // name after a reported actual rename; all retained recovery data persists.
    for (name, origin) in &before.objects {
        need(episode.final_path(origin).is_ok() && old_object(name).is_ok())?;
    }
    let committed = role.strip_suffix("-observe").and_then(role_case)
        .and_then(|case| episode.apps.iter().find(|(c, _)| *c == case))
        .is_some_and(|(_, account)| account.get("main.registryCommitted") == Ok("true"));
    if !committed {
        for key in ["registrationSha256", "registrationSecurityDigest", "registrationWrite", "registrationImage"] {
            need(previous.record.get(key)? == current.record.get(key)?)?;
        }
    } else if previous.record.get("registrationImage")? != "-" && current.record.get("registrationImage")? != "-" {
        need(previous.record.get("registrationSecurityDigest")? == current.record.get("registrationSecurityDigest")?)?;
    }
    if role == "damage-owned-shell" {
        need(previous.record.get("damagedShell")? == "-" && current.record.get("damagedShell")? != "-" && damage_tree.is_some())?;
    } else { need(previous.record.get("damagedShell")? == current.record.get("damagedShell")?)?; }
    if role == "stage-owned-foreign-selector" {
        need(previous.record.get("foreignSelector")? == "-" && d::digest(current.record.get("foreignSelector")?))?;
    } else { need(previous.record.get("foreignSelector")? == current.record.get("foreignSelector")?)?; }
    Ok(())
}
fn run(role: &'static str) -> Result<()> {
    let start = Instant::now();
    let test = selection_native_test(role)?;
    let root = selection_fixture_process(test)?;
    need(active_profile()? == SELECTION_FIXTURE_PROFILE)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let mut original = Fixture::new(start, root, image)?;
    // Chosen only by this admitted selection libtest before any file acquisition.
    original.lifetime_open_limit = open_budget(role)?;
    let mut observer = Observer::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (pre, pre_raw) = original.retained_precheck_for(SELECTION_FIXTURE_PROFILE)?;
        let pf = original.os_location()?;
        let (episode, previous) = original.selection_proofs(&pre, &pre_raw, role)?;
        let (system, begin, _) = original.selection_os_location(LocationKind::System)?;
        observer.initialize(&Boundary { original: RefCell::new(&mut original) }, &system.path)?;
        original.book.recheck_location(&system)?; original.gate()?;
        original.retained_close_from(begin)?;
        let registry = observer.registration(&Boundary { original: RefCell::new(&mut original) })?;
        if role == "stage-fresh" {
            // All three fresh absences are observed before the first source
            // create; no historical five-case episode may have used this VM.
            need(!registry.present)?;
            let (programs, begin, index) = original.selection_os_location(LocationKind::CommonPrograms)?;
            original.absent(index, d::SHORTCUT)?;
            original.book.recheck_location(&programs)?; original.gate()?;
            original.retained_close_from(begin)?;
        }
        let staged = if let Some(case) = SOURCES.into_iter().find(|c| role == source_stage(*c)) {
            // Capacity refusal happens before any source-directory mutation.
            need(original.files.len() <= 19)?;
            let input = installer_fixture_inputs(case)?;
            Some((case, original.retained_stage(&input, pf)?))
        } else { None };
        let (damaged, damage_tree) = if role == "damage-owned-shell" {
            let (object, tree) = original.selection_damage(previous.as_ref().ok_or(Error::Unsafe)?)?;
            (Some(object), Some(tree))
        } else {
            (previous.as_ref().map(|s| s.record.get("damagedShell").and_then(damage_object)).transpose()?.flatten(), None)
        };
        let foreign = if role == "stage-owned-foreign-selector" {
            Some(original.selection_foreign(previous.as_ref().ok_or(Error::Unsafe)?, &mut observer)?)
        } else {
            previous.as_ref().map(|s| s.record.get("foreignSelector").map(|v| (v != "-").then(|| v.to_owned())))
                .transpose()?.flatten()
        };
        let snapshot = original.selection_snapshot(&pre, &pre_raw, role, &episode, &mut observer, &registry,
            pf, staged, damaged.as_ref(), foreign.as_deref(), previous.as_ref())?;
        check_transition(previous.as_ref(), &snapshot, &episode, role, damage_tree.as_ref())?;
        observer.recheck_registration(&Boundary { original: RefCell::new(&mut original) })?;
        original.final_inputs()?;
        Ok(snapshot)
    })).unwrap_or(Err(Error::Unknown));
    if matches!(result, Err(Error::Unknown)) || original.unknown() || observer.unknown() {
        diagnostic_data("selection-fixture-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut observer)); }
    }
    let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observer.settle_once(&Boundary { original: RefCell::new(&mut original) });
        need(observer.closed())
    })).unwrap_or(Err(Error::Unknown));
    if closed.is_err() || observer.unknown() || !observer.closed() || original.unknown() {
        diagnostic_data("selection-fixture-primitive-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut observer)); }
    }
    let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original.settle())).unwrap_or(Err(Error::Unknown));
    if matches!(settled, Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("selection-fixture-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &mut observer)); }
    }
    let mut snapshot = result?; settled?;
    snapshot.record.put("fileOriginals", original.opened);
    snapshot.record.put("fileOriginalsClosed", original.closed);
    snapshot.record.put("parentBookSettled", "true");
    snapshot.record.put("selectionPrimitivesClosed", "true");
    snapshot.record.put("unknown", "false");
    snapshot.record.put("resultCloseGate", "original-fixture-exit-zero-required");
    let mut raw = snapshot.record.encoded(HEADER, KEYS, OWNER_LIMIT)?;
    for tree in &snapshot.trees { raw.extend(tree.line().as_bytes()); }
    for object in &snapshot.objects { raw.extend(object.line().as_bytes()); }
    parse_snapshot(&raw)?;
    original.gate()?;
    write_fixture_record(&original.root.join(result_name(role)?), &raw, OWNER_LIMIT, original.end)?;
    original.gate()
}
macro_rules! fixed_native {
    ($name:ident, $role:literal) => {
        #[test]
        #[ignore = "independent fresh hosted selection VM, actual ordered OUTER originals required"]
        fn $name() -> Result<()> { run($role) }
    };
}
fixed_native!(stage_fresh, "stage-fresh");
fixed_native!(observe_preview_fresh, "preview-fresh-observe");
fixed_native!(observe_select_fresh, "select-fresh-observe");
fixed_native!(stage_reuse, "stage-reuse");
fixed_native!(observe_preview_reuse, "preview-reuse-observe");
fixed_native!(observe_select_reuse, "select-reuse-observe");
fixed_native!(observe_preview_verify_reuse, "preview-verify-reuse-observe");
fixed_native!(observe_verify_reuse, "verify-reuse-observe");
fixed_native!(observe_preview_remove_reuse, "preview-remove-reuse-observe");
fixed_native!(observe_remove_reuse, "remove-reuse-observe");
fixed_native!(observe_refuse_stale_repair, "refuse-stale-repair-observe");
fixed_native!(observe_preview_repair_reuse, "preview-repair-reuse-observe");
fixed_native!(observe_repair_reuse, "repair-reuse-observe");
fixed_native!(observe_preview_registry_conflict, "preview-registry-conflict-observe");
fixed_native!(observe_registry_conflict, "registry-conflict-observe");
fixed_native!(stage_wrong_caller, "stage-wrong-caller");
fixed_native!(observe_preview_stop_old, "preview-stop-old-observe");
fixed_native!(observe_stop_old, "stop-old-observe");
fixed_native!(observe_preview_previous, "preview-previous-observe");
fixed_native!(observe_recover_previous, "recover-previous-observe");
fixed_native!(stage_bad_manifest, "stage-bad-manifest");
fixed_native!(observe_preview_stop_new, "preview-stop-new-observe");
fixed_native!(observe_stop_new, "stop-new-observe");
fixed_native!(observe_preview_current, "preview-current-observe");
fixed_native!(observe_recover_current, "recover-current-observe");
fixed_native!(damage_owned_shell, "damage-owned-shell");
fixed_native!(observe_preview_remove_damaged, "preview-remove-damaged-observe");
fixed_native!(observe_remove_damaged, "remove-damaged-observe");
fixed_native!(stage_owned_foreign_selector, "stage-owned-foreign-selector");
fixed_native!(observe_refuse_foreign_selector, "refuse-foreign-selector-observe");

#[test]
fn selection_lifetime_capacity_is_per_original_and_does_not_widen_live_or_legacy() -> Result<()> {
    assert_eq!(LIFETIME_OPENS, 804);
    for role in SELECTION_EPISODE_ROLES {
        if selection_native_test(role).is_ok() { assert!(open_budget(role)? <= LIFETIME_OPENS); }
    }
    assert_eq!(open_budget("stage-bad-manifest"), Ok(753));
    assert_eq!(open_budget("refuse-foreign-selector-observe"), Ok(748));
    assert_eq!(open_budget("damage-owned-shell"), Ok(804));
    assert_eq!(open_budget("stage-owned-foreign-selector"), Ok(756));
    assert!(open_budget("not-a-role").is_err());
    let base = Fixture::new(Instant::now(), PathBuf::from(r"C:\fixed"), PathBuf::from(r"C:\fixed\native.exe"))?;
    assert_eq!(base.lifetime_open_limit, 256);
    assert!(fixture_capacity(19, 8, 39, 2).is_err());
    Ok(())
}
#[test]
fn fixed_recovery_masks_and_effect_origin_names_are_unambiguous() {
    // Pure DATA: no OS calls or native digest in this unit test. Native complete
    // trees and their mutations are tested through the same original workflow.
    assert_eq!(expected_phase_mask(SelectionCase::StopOld), 3);
    assert_eq!(expected_phase_mask(SelectionCase::StopNew), 15);
    assert_eq!(previous_returns(1, true, false), Vec::<u8>::new());
    assert_eq!(previous_returns(2, true, false).len(), 10);
    assert_eq!(previous_returns(6, true, true).len(), 35);
    let origin = Origin { directory: false, case: "select-fresh".to_owned(), path: "selection/recovery/a/incoming.lnk".to_owned() };
    assert_ne!(origin, Origin { path: "selector".to_owned(), ..origin.clone() });
}

#[test]
fn complete_tree_commitment_covers_all_rows_metadata_content_acl_and_roster() -> Result<()> {
    // Exercise the exact complete encoding given to the native SHA256 call;
    // no OS API or synthetic receipt is used by this DATA regression.
    let objects: Vec<_> = (0..63).map(|i| ObservedObject {
        role: format!("row-{i:02}"), directory: i < 9,
        stamp: Stamp { volume: 1, id: [i as u8 + 1; 16], creation: 1, write: 2,
            change: 3, size: if i < 9 { 0 } else { 4 }, allocation: 8, links: 1,
            attributes: if i < 9 { FS::FILE_ATTRIBUTE_DIRECTORY } else { FS::FILE_ATTRIBUTE_NORMAL } },
        security: "a".repeat(64), sha: if i < 9 { "-".to_owned() } else { "b".repeat(64) },
        inventory: if i < 9 { "c".repeat(64) } else { "-".to_owned() },
    }).collect();
    let encode = |value: Vec<ObservedObject>| complete_tree_bytes("source/fresh", value).map(|row| row.3);
    let original = encode(objects.clone())?;
    let mut reordered = objects.clone(); reordered.reverse(); assert_eq!(encode(reordered)?, original);
    assert_ne!(complete_tree_bytes("source/reuse", objects.clone())?.3, original);
    for index in 0..objects.len() {
        for field in 0..12 {
            let mut changed = objects.clone(); let item = &mut changed[index];
            match field {
                0 => item.role.push('x'), 1 => item.stamp.volume += 1, 2 => item.stamp.id[0] ^= 128,
                3 => item.stamp.creation += 1, 4 => item.stamp.write += 1, 5 => item.stamp.change += 1,
                6 => item.stamp.size += 1, 7 => item.stamp.allocation += 1, 8 => item.stamp.links += 1,
                9 => item.stamp.attributes |= FS::FILE_ATTRIBUTE_READONLY,
                10 => item.security = "d".repeat(64),
                _ => if item.directory { item.inventory = "e".repeat(64) } else { item.sha = "f".repeat(64) },
            }
            assert_ne!(encode(changed)?, original, "row {index}, field {field}");
        }
    }
    let mut missing = objects.clone(); missing.pop(); assert!(complete_tree_bytes("source/fresh", missing).is_err());
    let mut duplicate = objects.clone(); duplicate[1] = duplicate[0].clone();
    assert!(complete_tree_bytes("source/fresh", duplicate).is_err());
    let mut kind = objects; kind[0].directory = false;
    assert!(complete_tree_bytes("source/fresh", kind).is_err());
    Ok(())
}
#[test]
fn extra_or_reordered_rename_cycles_are_not_hidden_by_final_names() {
    use super::super::super::installer_selection_fixture_data::SelectionAccountingOutput as Output;
    let root = format!("selection/recovery/{}", "a".repeat(32));
    let mut account = SelectionAccounting { fields: [
        ("recoveryRun".to_owned(), "a".repeat(32)), ("main.oldMoveEntered".to_owned(), "true".to_owned()),
        ("main.newMoveEntered".to_owned(), "true".to_owned())].into_iter().collect(),
        outputs: vec![
            Output { kind: d::OutputKind::Rename, path: "selector".to_owned(),
                destination: Some(format!("{root}/previous.lnk")), native_return: (1, 0) },
            Output { kind: d::OutputKind::Rename, path: format!("{root}/incoming.lnk"),
                destination: Some("selector".to_owned()), native_return: (1, 0) },
        ], competitor_outputs: Vec::new() };
    assert!(validate_rename_routes(&account).is_ok());
    account.outputs.reverse(); assert!(validate_rename_routes(&account).is_err());
    account.outputs.reverse(); account.outputs.extend(account.outputs.clone());
    assert!(validate_rename_routes(&account).is_err());
}
