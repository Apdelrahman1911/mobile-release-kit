//! One finite project-field journey through the original installed Mac UI.
//! Only observation DATA and disposable fixture mutations live here. The real
//! document, panel, SourceBook, child and relay remain the sole effect owners.
use std::{fs::{File, OpenOptions}, os::{fd::AsFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Path, PathBuf}, sync::{Arc, OnceLock, Weak, atomic::{AtomicBool, Ordering}}, time::Instant};
use serde_json::{json, Value};
use crate::{asset_commands::{self as input, ProjectPathField as Field, Reason},
    asset_session::{DocumentBinding, InstalledMacSessionSnapshot, OriginalWork}, error::BridgeError};
use mrk_macos_installed_native::{PanelKind, ProjectFieldPreparation, VersionSourceNamePreparation};
use super::{Case, Observation};

pub(super) const NAME: &str = "project-fields";
pub(super) const COUNT: usize = 10;
const LINK_BYTES: &[u8] = b"MRK_PROJECT_FIELD_LINK_ORIGINAL\n";
const KIND_BYTES: &[u8] = b"MRK_PROJECT_FIELD_KIND_ORIGINAL\n";

#[derive(Clone, Copy)]
pub(super) struct Choice {
    pub(super) field: Field, pub(super) name: &'static str, label: &'static str,
    pub(super) relative: Option<&'static str>, pub(super) reason: Reason,
}
pub(super) const CHOICES: [Choice; COUNT] = [
    Choice { field: Field::VersionSource, name: "version.source", label: "Committed version file", relative: Some("inputs/VERSION"), reason: Reason::None },
    Choice { field: Field::IosProject, name: "ios.project", label: "Xcode project", relative: Some("ios/Example.xcodeproj"), reason: Reason::None },
    Choice { field: Field::IosWorkspace, name: "ios.workspace", label: "Xcode workspace", relative: Some("ios/Example.xcworkspace"), reason: Reason::None },
    Choice { field: Field::MetadataRoot, name: "metadata.root", label: "Store metadata folder", relative: Some("metadata"), reason: Reason::None },
    Choice { field: Field::VersionSource, name: "version.source", label: "Committed version file", relative: None, reason: Reason::UserCancelled },
    Choice { field: Field::MetadataRoot, name: "metadata.root", label: "Store metadata folder", relative: None, reason: Reason::UserCancelled },
    Choice { field: Field::VersionSource, name: "version.source", label: "Committed version file", relative: None, reason: Reason::SourceRefused },
    Choice { field: Field::VersionSource, name: "version.source", label: "Committed version file", relative: None, reason: Reason::SourceRefused },
    Choice { field: Field::VersionSource, name: "version.source", label: "Committed version file", relative: None, reason: Reason::SourceRefused },
    Choice { field: Field::IosWorkspace, name: "ios.workspace", label: "Xcode workspace", relative: None, reason: Reason::SourceChanged },
];
pub(super) fn index(id: u32) -> Option<u8> { id.checked_sub(2).filter(|n| *n < COUNT as u32).map(|n| n as u8) }
pub(super) fn id(i: u8) -> Option<u32> { (usize::from(i) < COUNT).then_some(u32::from(i) + 2) }
pub(super) fn accepts(i: u8) -> bool { usize::from(i) < COUNT && !matches!(i, 4 | 5) }
pub(super) fn kind(i: u8) -> Option<PanelKind> { Some(match CHOICES.get(usize::from(i))?.field {
    Field::VersionSource => PanelKind::VersionSource, Field::IosProject => PanelKind::IosProject,
    Field::IosWorkspace => PanelKind::IosWorkspace, Field::MetadataRoot => PanelKind::MetadataRoot,
}) }
pub(super) fn kind_name(i: u8) -> Option<&'static str> { Some(match CHOICES.get(usize::from(i))?.field {
    Field::VersionSource => "version-source", Field::IosProject => "ios-project",
    Field::IosWorkspace => "ios-workspace", Field::MetadataRoot => "metadata-root",
}) }
pub(super) fn targets(project: &Path) -> Option<Vec<PathBuf>> {
    Some(vec![project.join("inputs/VERSION"), project.join("ios/Example.xcodeproj"),
        project.join("ios/Example.xcworkspace"), project.join("metadata"),
        project.join("inputs/VERSION"), project.join("metadata"),
        project.parent()?.join("state/project-fields/outside/VERSION"), project.join("inputs/link-input"),
        project.join("inputs/kind-input"), project.join("ios/Example.xcworkspace")])
}

/// Neither clonable nor constructible by IPC. The exact original document is
/// consumed before navigation, and the returned registration is observed once.
pub(crate) struct Registration { control: Arc<Control>, document: Weak<()> }
pub(crate) struct Control {
    original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>,
    normal_available: OnceLock<bool>, claimed: AtomicBool, returned: AtomicBool,
}
impl Control {
    pub(super) fn new() -> Arc<Self> { Arc::new(Self { original: OnceLock::new(), document: OnceLock::new(),
        normal_available: OnceLock::new(), claimed: AtomicBool::new(false), returned: AtomicBool::new(false) }) }
    fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| q.case == Case::ProjectFields
            && q.project_fields.as_ref().is_some_and(|c| std::ptr::eq(c.as_ref(), self)))
    }
    pub(crate) fn bound(&self, document: &Arc<()>) -> bool {
        // Historical binding, not live action permission. In particular it
        // remains observable for ordinary original Quit cleanup after failure.
        self.claimed.load(Ordering::SeqCst) && self.returned.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some_and(|d| Arc::ptr_eq(&d, document))
            && self.observation().is_some()
    }
    pub(crate) fn permits(&self, document: &Arc<()>) -> bool {
        self.bound(document) && self.observation().is_some_and(|q| q.timely())
    }
    pub(super) fn registered(&self) -> Option<bool> {
        (self.claimed.load(Ordering::SeqCst) && self.returned.load(Ordering::SeqCst))
            .then(|| self.normal_available.get().copied()).flatten()
    }
    fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &DocumentBinding) -> Result<(), BridgeError> {
        if q.case != Case::ProjectFields || std::thread::current().id() != q.main || !q.timely() {
            return Err(BridgeError::invalid());
        }
        let identity = document.installed_macos_project_fields_identity();
        if identity.upgrade().is_none() || self.original.set(Arc::downgrade(q)).is_err()
            || self.document.set(identity.clone()).is_err() { return Err(BridgeError::invalid()); }
        document.register_installed_macos_project_fields(Registration { control: self.clone(), document: identity })?;
        if self.returned.swap(true, Ordering::SeqCst) { return Err(BridgeError::invalid()); }
        Ok(())
    }
}
impl Registration {
    pub(crate) fn consume(self, document: &Arc<()>, normal_available: bool) -> Result<Arc<Control>, BridgeError> {
        let q = self.control.observation().ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !r.attached || r.started || r.loaded || !q.timely()
            || !self.document.upgrade().is_some_and(|d| Arc::ptr_eq(&d, document))
            || self.control.normal_available.set(normal_available).is_err()
            || self.control.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        drop(r); Ok(self.control)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate(u8), Section(u8), Browse(u8), Native(u8), Chosen(u8), Read(u8),
    PreviewPage, Preview, Previewed, Done }
fn needs_name(i: u8) -> bool { kind(i) == Some(PanelKind::VersionSource) && accepts(i) }
#[derive(Clone, Default)]
struct Row {
    requested: bool, returned: bool, selected_returned: bool,
    preparation: Option<ProjectFieldPreparation>, name_preparation: Option<VersionSourceNamePreparation>, source_started: Option<bool>,
    native_settled: bool, visible: bool,
}
#[derive(Clone)]
pub(super) struct Record {
    rows: [Row; COUNT], completed: usize, preview_requested: bool, preview_returned: bool, preview_visible: bool,
    original_count: usize, all_settled: bool,
}
impl Record {
    pub(super) fn new() -> Self { Self { rows: std::array::from_fn(|_| Row::default()), completed: 0,
        preview_requested: false, preview_returned: false, preview_visible: false, original_count: 0, all_settled: false } }
    fn row(&mut self, i: u8) -> Option<&mut Row> {
        (usize::from(i) == self.completed).then(|| self.rows.get_mut(usize::from(i))).flatten()
    }
    pub(super) fn navigation_prepared(&self, i: u8) -> bool {
        self.rows.get(usize::from(i)).is_some_and(|r| kind(i).is_some_and(|k|
            r.preparation.is_some_and(|p| p.succeeded(k, accepts(i)))))
    }
    pub(super) fn prepared(&self, i: u8) -> bool {
        self.navigation_prepared(i) && self.rows.get(usize::from(i)).is_some_and(|r|
            if needs_name(i) { r.name_preparation.is_some_and(|p| p.succeeded()) } else { r.name_preparation.is_none() })
    }
    pub(super) fn name_pending(&self, i: u8) -> bool {
        needs_name(i) && usize::from(i) == self.completed && self.navigation_prepared(i)
            && self.rows.get(usize::from(i)).is_some_and(|r| r.requested && !r.native_settled && r.name_preparation.is_none())
    }
    pub(super) fn name_preparation_sample(&self, i: u8) -> Option<VersionSourceNamePreparation> {
        self.rows.get(usize::from(i))?.name_preparation
    }
    pub(super) fn name_preparation(&mut self, i: u8, value: VersionSourceNamePreparation) -> bool {
        if !self.name_pending(i) { return false; }
        let Some(row) = self.row(i) else { return false; };
        // Every returned attempt occupies this separate slot, including a
        // refused/exceptional/unknown phase. There is no retry/reset transition.
        row.name_preparation = Some(value);
        value.succeeded()
    }
    pub(super) fn preparation_sample(&self, i: u8) -> Option<ProjectFieldPreparation> {
        self.rows.get(usize::from(i))?.preparation
    }
    pub(super) fn preparation(&mut self, i: u8, value: ProjectFieldPreparation) -> bool {
        let Some(row) = self.row(i) else { return false; };
        if !row.requested || row.preparation.is_some() { return false; }
        // A nonattempted WouldBlock is a readiness sample, not a second permit.
        if value.result == "would-block" && value.facts == Some(0) { return true; }
        row.preparation = Some(value);
        kind(i).is_some_and(|k| value.succeeded(k, accepts(i)))
    }
    pub(super) fn ready_for_native(&self, i: u8, snapshot: &InstalledMacSessionSnapshot) -> bool {
        usize::from(i) == self.completed && self.rows.get(usize::from(i)).is_some_and(|row|
            row.requested && row.returned && !row.native_settled)
            && id(i).is_some_and(|id| snapshot.originals == id as usize) && snapshot.originals_settled && snapshot.empty
    }
    pub(super) fn native_finished(&mut self, i: u8, document: &DocumentBinding, target: &Path) -> bool {
        let Some(choice) = CHOICES.get(usize::from(i)) else { return false; };
        let Some(id) = id(i) else { return false; };
        let Some((witness, started)) = document.installed_macos_project_path_original(id, choice.field, accepts(i)) else { return false; };
        if !self.prepared(i) || witness.selected.as_deref() != accepts(i).then_some(target) || !witness.callback_returned
            || started != (accepts(i) && i != 6) { return false; }
        let Some(row) = self.row(i) else { return false; };
        if row.native_settled || row.selected_returned != accepts(i) || !row.returned { return false; }
        row.source_started = Some(started); row.native_settled = true; true
    }
    pub(super) fn observe(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        // A coordinator may have staged its result before the relay consumes
        // it. That transient private state is not a failed native journey.
        // Empty/final originals are required at the actual transition below.
        if snapshot.originals > 12 || snapshot.originals < self.original_count { return false; }
        self.original_count = snapshot.originals; self.all_settled = snapshot.originals_settled; true
    }
    pub(super) fn final_originals(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        self.observe(snapshot) && self.completed == COUNT && snapshot.originals == 12 && snapshot.originals_settled && snapshot.empty
    }
    pub(super) fn dom(&mut self, step: Step, value: &Value) -> Result<Step, ()> {
        if let Step::Read(i) = step {
            let choice = CHOICES.get(usize::from(i)).ok_or(())?;
            let expected_value = match choice.field { Field::VersionSource => "inputs/VERSION", Field::IosProject => "ios/Example.xcodeproj",
                Field::IosWorkspace => "ios/Example.xcworkspace", Field::MetadataRoot => "metadata" };
            let notice = match choice.reason {
                Reason::None => None,
                Reason::UserCancelled => Some("Selection cancelled. No draft or baseline was changed."),
                Reason::SourceRefused => Some("Choose a supported existing item inside the current project. Outside paths, links and unsupported item kinds are refused."),
                Reason::SourceChanged => Some("The selected item or project changed during selection. No draft or baseline was changed."),
                _ => return Err(()),
            };
            let pair = matches!(i, 2 | 9).then(|| json!(["ios/Example.xcodeproj", "ios/Example.xcworkspace"]));
            if value != &json!({"state":"ready","value":expected_value,"dirty":true,"browse":true,
                "notice":notice,"pair":pair}) { return Err(()); }
            let row = self.row(i).ok_or(())?;
            if !row.native_settled || row.visible { return Err(()); }
            row.visible = true; self.completed += 1;
            return Ok(if self.completed == COUNT { Step::PreviewPage } else { Step::Navigate(i + 1) });
        }
        if value != &json!({"state":"ready"}) { return Err(()); }
        Ok(match step {
            Step::Navigate(i) if usize::from(i) == self.completed => Step::Section(i),
            Step::Section(i) if usize::from(i) == self.completed => Step::Browse(i),
            Step::Browse(i) if usize::from(i) == self.completed => Step::Native(i),
            Step::PreviewPage if self.completed == COUNT => Step::Preview,
            Step::Preview if self.completed == COUNT => Step::Previewed,
            Step::Previewed if self.preview_requested && self.preview_returned && !self.preview_visible => {
                self.preview_visible = true; Step::Done
            },
            _ => return Err(()),
        })
    }
    pub(super) fn report(&self, registered: Option<bool>, restored: bool) -> Option<Value> {
        let normal = registered?;
        if self.completed != COUNT || self.original_count != 12 || !self.all_settled || !restored
            || !self.preview_requested || !self.preview_returned || !self.preview_visible { return None; }
        let rows = self.rows.iter().enumerate().map(|(n, row)| {
            let i = n as u8; let choice = CHOICES[n]; let preparation = row.preparation?;
            if !row.requested || !row.returned || row.selected_returned != accepts(i) || !row.native_settled || !row.visible
                || !self.prepared(i) || row.source_started != Some(accepts(i) && i != 6) { return None; }
            Some(json!({"operationId":id(i)?,"field":choice.name,"kind":kind_name(i)?,
                "nativeResponse":if accepts(i) { "accept" } else { "decline" },
                "initialRootAndOptions":{"result":preparation.result,"facts":preparation.facts,"fileFilter":super::file_filter_value(preparation.file_filter)},
                "nameFieldPreparation":row.name_preparation.map(|name| json!({"returned":true,"result":name.result,"facts":name.facts})),
                "laterSyntheticNavigation":accepts(i),"exactNativeSelection":accepts(i).then_some(true),
                "sourceBookStarted":row.source_started,"originalSourceChildGuiAndCoordinatorSettled":row.native_settled,
                "relativePath":choice.relative,"errorCode":matches!(choice.reason, Reason::SourceRefused | Reason::SourceChanged)
                    .then(|| input::project_path_error(choice.reason).code),"draftObserved":row.visible}))
        }).collect::<Option<Vec<_>>>()?;
        Some(json!({"schemaVersion":2,"oneUseOriginalDocumentRegistration":true,"normalProfileAvailable":normal,
            "selection":"original-bound-installed-macos-project-fields","rows":rows,"originalOperations":12,
            "allOriginalsSettled":self.all_settled,"completeDraftAndBaselineMatched":self.preview_visible,
            "previewValidation":"invalid-retained-ios-fields","fixtureMutationsRestored":restored,
            "shippingProfileEnabledByThisReceipt":false}))
    }
}

fn expected_draft(base: &Value) -> Value {
    let mut draft = base.clone(); draft["version"]["source"] = json!("inputs/VERSION");
    draft["ios"]["project"] = json!("ios/Example.xcodeproj"); draft["ios"]["workspace"] = json!("ios/Example.xcworkspace");
    draft["metadata"]["root"] = json!("metadata"); draft
}
impl Observation {
    pub(crate) fn attach_project_fields(self: &Arc<Self>, document: &DocumentBinding) -> Result<(), BridgeError> {
        match self.project_fields.as_ref() { Some(control) => control.attach(self, document), None => Ok(()) }
    }
    pub(crate) fn path_request(&self, args: &input::ChooseProjectPath<'_>) {
        let Some(mut r) = self.record() else { return; };
        let i = match r.step { super::Step::ProjectFields(Step::Browse(i) | Step::Native(i)) => i,
            _ => { self.fail_with("project-fields-request-contract"); return; } };
        let valid = self.case == Case::ProjectFields && self.timely()
            && r.project.as_ref().is_some_and(|p| p.id == args.project_id)
            && CHOICES.get(usize::from(i)).is_some_and(|c| c.field == args.field);
        let row = r.project_field_record.as_mut().and_then(|record| record.row(i));
        if !valid || !row.is_some_and(|row| { if row.requested { false } else { row.requested = true; true } }) {
            self.fail_with("project-fields-request-contract");
        }
    }
    pub(crate) fn path_result(&self, result: &Result<Option<input::ProjectPathResult>, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let i = match r.step { super::Step::ProjectFields(Step::Native(i) | Step::Chosen(i)) => i,
            _ => { self.fail_with("project-fields-result-contract"); return; } };
        let Some(choice) = CHOICES.get(usize::from(i)) else { self.fail_with("project-fields-result-contract"); return; };
        let matched = match (result, choice.reason) {
            (Ok(None), Reason::UserCancelled) => true,
            (Ok(Some(value)), Reason::None) => r.project.as_ref().is_some_and(|p| serde_json::to_value(value).ok()
                == Some(json!({"projectId":p.id,"field":choice.name,"relativePath":choice.relative}))),
            (Err(error), Reason::SourceRefused | Reason::SourceChanged) => *error == input::project_path_error(choice.reason),
            _ => false,
        };
        if self.case != Case::ProjectFields || !self.timely() || !matched
            || !r.project_field_record.as_mut().and_then(|record| record.row(i)).is_some_and(|row| {
                if !row.requested || row.returned { false } else { row.returned = true; true }
            }) { self.fail_with("project-fields-result-contract"); }
    }
    pub(crate) fn path_selected(&self, document: &DocumentBinding, owner: &Arc<OriginalWork>, field: Field, path: &Path) -> bool {
        if self.case != Case::ProjectFields { return false; }
        let Some(i) = index(owner.id) else { self.fail_with("project-fields-original-contract"); return false; };
        let valid = self.timely() && !owner.interrupted() && CHOICES[usize::from(i)].field == field
            && accepts(i) && self.field_paths.get(usize::from(i)).is_some_and(|target| target == path)
            && document.installed_macos_project_path_before_probe(owner, field, path);
        let Some(mut r) = self.record() else { return false; };
        let step_matches = matches!(r.step, super::Step::ProjectFields(Step::Native(n) | Step::Chosen(n)) if n == i);
        if !valid || !step_matches || !r.project_field_record.as_ref().is_some_and(|record| record.prepared(i))
            || !r.project_field_record.as_mut().and_then(|record| record.row(i)).is_some_and(|row| {
                if !row.requested || row.selected_returned { false } else { row.selected_returned = true; true }
            }) { self.fail_with("project-fields-original-contract"); return false; }
        let root = r.fixture.root.clone(); let uid = r.fixture.uid;
        if let Some(fixture) = r.fixture.project_fields.as_mut() {
            if fixture.mutate(i, &root, uid, self.end, &self.failed).is_ok() && self.timely() { return true; }
        }
        self.fail_with("project-fields-fixture-contract"); false
    }
    pub(super) fn project_fields_preview_request(&self, base: &Value, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        let ready = matches!(r.step, super::Step::ProjectFields(Step::Preview | Step::Previewed)) && base == &self.base
            && draft == &expected_draft(&self.base) && self.timely();
        if !ready || !r.project_field_record.as_mut().is_some_and(|record| {
            if record.completed != COUNT || record.preview_requested { false } else { record.preview_requested = true; true }
        }) { self.fail_with("project-fields-request-contract"); }
    }
    pub(super) fn project_fields_preview_result(&self, result: &Result<Value, BridgeError>) {
        let valid = result.as_ref().is_ok_and(|v| v["schemaVersion"] == 1 && v["comparison"]["baseProvided"] == true
            // Browsing does not silently choose between project/workspace or
            // enable iOS. Both user selections remain; core must reject the
            // resulting configuration rather than claim release readiness.
            && v["validation"]["valid"] == false && v["validation"]["state"] == "invalid"
            && v["validation"]["issues"].as_array().is_some_and(|rows|
                rows.len() == 1 && rows[0]["code"] == "config.invalid")
            && super::assurance(v, "schema-policy")
            && v["comparison"]["state"] == "complete" && v["comparison"]["unreviewedCount"] == 0
            && v["comparison"]["counts"] == json!({"added":2,"changed":2,"removed":0}));
        let Some(mut r) = self.record() else { return; };
        if !valid || !self.timely() || !r.project_field_record.as_mut().is_some_and(|record| {
            if !record.preview_requested || record.preview_returned { false } else { record.preview_returned = true; true }
        }) { self.fail_with("project-fields-result-contract"); }
    }
}

/// Fixed fixture originals only. No user file is written or removed. Originals
/// temporarily renamed for kind/link refusal are preserved and restored with
/// the existing RENAME_EXCL adapter, never overwrite-capable rename.
pub(super) struct Fixture {
    files: Vec<(&'static str, super::FileFact)>, directories: Vec<(&'static str, [u64; 6])>,
    outside: super::FileFact, outside_root: [u64; 6], mutation: Option<Mutation>, restored: [bool; 3],
}
struct Mutation { index: u8, original: [u64; 9], temporary: [u64; 9], parent: [u64; 9] }
impl Fixture {
    pub(super) fn root_entries() -> &'static [&'static str] { &[".gitignore", "app", "inputs", "ios", "keep.txt", "metadata", "release", "version.properties"] }
    fn dirs() -> [(&'static str, u32, &'static [&'static str]); 8] { [
        (".", 0o700, Self::root_entries()), ("app", 0o700, &["build.gradle.kts"]),
        ("inputs", 0o700, &["VERSION", "kind-input", "link-input"]),
        ("ios", 0o700, &["Example.xcodeproj", "Example.xcworkspace"]),
        ("ios/Example.xcodeproj", 0o700, &[]), ("ios/Example.xcworkspace", 0o700, &[]),
        ("metadata", 0o700, &[]), ("release", 0o755, &["mobile-release.json"]),
    ] }
    fn bytes() -> Vec<(&'static str, Vec<u8>)> { vec![
        (".gitignore", super::Fixture::ignore_bytes(true, false)), ("app/build.gradle.kts", super::SOURCE.to_vec()),
        ("keep.txt", super::KEEP.to_vec()), ("version.properties", super::VERSION.to_vec()),
        ("release/mobile-release.json", super::CONFIG.to_vec()), ("inputs/VERSION", super::VERSION.to_vec()),
        ("inputs/link-input", LINK_BYTES.to_vec()), ("inputs/kind-input", KIND_BYTES.to_vec()),
    ] }
    fn outside(root: &Path) -> Result<PathBuf, ()> { Ok(root.parent().ok_or(())?.join("state/project-fields/outside")) }
    pub(super) fn file(&self, name: &str) -> Option<super::FileFact> { self.files.iter().find(|(n, _)| *n == name).map(|(_, f)| f.clone()) }
    pub(super) fn dir(&self, name: &str) -> Option<[u64; 6]> { self.directories.iter().find(|(n, _)| *n == name).map(|(_, d)| *d) }
    pub(super) fn capture(root: &Path, uid: u32) -> Result<Self, ()> {
        let directories = Self::dirs().into_iter().map(|(name, mode, entries)|
            Ok((name, super::directory(&root.join(name), uid, mode, entries)?))).collect::<Result<Vec<_>, ()>>()?;
        let files = Self::bytes().into_iter().map(|(name, bytes)| Ok((name, super::file_fact(&root.join(name), &bytes, uid)?)))
            .collect::<Result<Vec<_>, ()>>()?;
        let outside = Self::outside(root)?;
        Ok(Self { files, directories, outside: super::file_fact(&outside.join("VERSION"), super::VERSION, uid)?,
            outside_root: super::directory(&outside, uid, 0o700, &["VERSION"])?, mutation: None, restored: [false; 3] })
    }
    pub(super) fn verify(&self, root: &Path, uid: u32) -> Result<(), ()> {
        if self.mutation.is_some() { return Err(()); }
        for (name, mode, entries) in Self::dirs() {
            if Some(super::directory(&root.join(name), uid, mode, entries)?) != self.dir(name) { return Err(()); }
        }
        for (name, bytes) in Self::bytes() {
            if Some(super::file_fact(&root.join(name), &bytes, uid)?) != self.file(name) { return Err(()); }
        }
        let outside = Self::outside(root)?;
        if super::directory(&outside, uid, 0o700, &["VERSION"])? != self.outside_root
            || super::file_fact(&outside.join("VERSION"), super::VERSION, uid)? != self.outside { return Err(()); }
        Ok(())
    }
    pub(super) fn restored(&self) -> bool { self.mutation.is_none() && self.restored == [true; 3] }
    fn with_parent<T>(path: &Path, expected: [u64; 9], body: impl FnOnce(&File) -> Result<T, ()>) -> Result<T, ()> {
        let file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
            .open(path).map_err(|_| ())?;
        let result = (|| {
            if super::identity(&file.metadata().map_err(|_| ())?)? != expected
                || super::identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != expected { return Err(()); }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
            body(&file)
        })();
        if nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_err() { return Err(()); }
        result
    }
    pub(super) fn mutate(&mut self, i: u8, root: &Path, uid: u32, end: Instant, failed: &AtomicBool) -> Result<(), ()> {
        let current = || !failed.load(Ordering::SeqCst) && Instant::now() < end;
        if !current() || self.mutation.is_some() { return Err(()); }
        if i < 7 { return Ok(()); }
        if i > 9 || self.restored[usize::from(i - 7)] { return Err(()); }
        self.verify(root, uid)?;
        let parent = if i == 9 { root.to_path_buf() } else { root.join("inputs") };
        let before = super::identity(&std::fs::symlink_metadata(&parent).map_err(|_| ())?)?;
        let mutation = Self::with_parent(&parent, before, |file| {
            if !current() { return Err(()); }
            if i == 9 {
                file.set_permissions(std::fs::Permissions::from_mode(0o500)).map_err(|_| ())?;
                let after = super::identity(&file.metadata().map_err(|_| ())?)?;
                let mut expected = before; expected[2] = 0o40500; expected[8] = after[8];
                if after != expected || super::identity(&std::fs::symlink_metadata(&parent).map_err(|_| ())?)? != after { return Err(()); }
                return Ok(Mutation { index: i, original: before, temporary: after, parent: after });
            }
            let (name, saved) = if i == 7 { ("link-input", "link-original") } else { ("kind-input", "kind-original") };
            let original = self.file(&format!("inputs/{name}")).ok_or(())?.identity;
            if super::identity(&std::fs::symlink_metadata(parent.join(name)).map_err(|_| ())?)? != original || !current() { return Err(()); }
            mrk_macos_installed_native::publish_directory(file.as_fd(), name, file.as_fd(), saved).map_err(|_| ())?;
            if !current() { return Err(()); }
            let preserved = super::identity(&std::fs::symlink_metadata(parent.join(saved)).map_err(|_| ())?)?;
            if preserved[..8] != original[..8] { return Err(()); }
            if i == 7 { nix::unistd::symlinkat("VERSION", file.as_fd(), name).map_err(|_| ())?; }
            else { nix::sys::stat::mkdirat(file.as_fd(), name, nix::sys::stat::Mode::S_IRWXU).map_err(|_| ())?; }
            let temporary = super::identity(&std::fs::symlink_metadata(parent.join(name)).map_err(|_| ())?)?;
            let kind = temporary[2] & 0o170000;
            if temporary[3] != u64::from(uid) || temporary[..2] == original[..2]
                || kind != if i == 7 { 0o120000 } else { 0o40000 }
                || i == 7 && (temporary[5] != 1 || std::fs::read_link(parent.join(name)).map_err(|_| ())? != Path::new("VERSION")) { return Err(()); }
            let after = super::identity(&file.metadata().map_err(|_| ())?)?;
            if after[..5] != before[..5] || super::identity(&std::fs::symlink_metadata(&parent).map_err(|_| ())?)? != after { return Err(()); }
            Ok(Mutation { index: i, original: preserved, temporary, parent: after })
        })?;
        self.mutation = Some(mutation);
        current().then_some(()).ok_or(())
    }
    pub(super) fn restore(&mut self, i: u8, root: &Path, uid: u32, end: Instant, failed: &AtomicBool) -> Result<(), ()> {
        let current = || !failed.load(Ordering::SeqCst) && Instant::now() < end;
        if !current() { return Err(()); }
        if i < 7 { return self.mutation.is_none().then_some(()).ok_or(()); }
        let mutation = self.mutation.as_ref().filter(|m| m.index == i).ok_or(())?;
        let parent = if i == 9 { root.to_path_buf() } else { root.join("inputs") };
        let restored = Self::with_parent(&parent, mutation.parent, |file| {
            if !current() { return Err(()); }
            if i == 9 {
                if super::identity(&file.metadata().map_err(|_| ())?)? != mutation.temporary { return Err(()); }
                file.set_permissions(std::fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
                let after = super::identity(&file.metadata().map_err(|_| ())?)?;
                if after[..8] != mutation.original[..8] || super::identity(&std::fs::symlink_metadata(&parent).map_err(|_| ())?)? != after { return Err(()); }
                return Ok(after);
            }
            let (name, saved) = if i == 7 { ("link-input", "link-original") } else { ("kind-input", "kind-original") };
            if super::identity(&std::fs::symlink_metadata(parent.join(name)).map_err(|_| ())?)? != mutation.temporary
                || super::identity(&std::fs::symlink_metadata(parent.join(saved)).map_err(|_| ())?)? != mutation.original { return Err(()); }
            if i == 7 {
                if std::fs::read_link(parent.join(name)).map_err(|_| ())? != Path::new("VERSION") { return Err(()); }
            } else { super::directory(&parent.join(name), uid, 0o700, &[])?; }
            if !current() { return Err(()); }
            // Remove only this captured temporary link/empty directory, never
            // the preserved original. A failed unlink/rename is never retried.
            nix::unistd::unlinkat(file.as_fd(), name, if i == 7 { nix::unistd::UnlinkatFlags::NoRemoveDir }
                else { nix::unistd::UnlinkatFlags::RemoveDir }).map_err(|_| ())?;
            if !current() { return Err(()); }
            mrk_macos_installed_native::publish_directory(file.as_fd(), saved, file.as_fd(), name).map_err(|_| ())?;
            let after = super::identity(&std::fs::symlink_metadata(parent.join(name)).map_err(|_| ())?)?;
            if after[..8] != mutation.original[..8] { return Err(()); }
            Ok(after)
        })?;
        if !current() { return Err(()); }
        if i != 9 {
            let name = if i == 7 { "inputs/link-input" } else { "inputs/kind-input" };
            let original = self.files.iter_mut().find(|(n, _)| *n == name).ok_or(())?;
            // Rename changes ctime only; original inode/bytes/mode stay bound.
            original.1.identity = restored;
        }
        self.mutation = None; self.restored[usize::from(i - 7)] = true;
        self.verify(root, uid)?; current().then_some(()).ok_or(())
    }
}

/// Ordinary DOM navigation, clicks and value reads only. No React state, IPC,
/// native path, result or completion is injected by this script.
pub(super) fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Navigate(i) => format!("return nav({});", serde_json::to_string(if matches!(i, 3 | 5) { "Metadata" } else { "Project settings" }).ok()?),
        Step::Section(i) if matches!(i, 3 | 5) => "return ready();".into(),
        Step::Section(i) => format!("const b=[...document.querySelectorAll('[aria-label=\"Settings section\"] button')].find(b=>text(b)==={});if(!b||b.disabled)return wait();show(b);b.click();return ready();", serde_json::to_string(if matches!(i, 1 | 2 | 9) { "iOS" } else { "General" }).ok()?),
        Step::Browse(i) => format!("const f=field({});if(!f||f.button.disabled)return wait();show(f.button);if(text(f.button)!=='Browse existing…')throw 0;f.button.click();return ready();", serde_json::to_string(CHOICES.get(usize::from(i))?.label).ok()?),
        Step::Read(i) => {
            let pair = if matches!(i, 2 | 9) { "[field('Xcode project').input.value,field('Xcode workspace').input.value]" } else { "null" };
            format!("const f=field({}),banner=document.querySelector('.draft-banner');if(!f||f.button.disabled||!banner||text(f.button)!=='Browse existing…')return wait();show(f.input);const notices=[...document.querySelectorAll('main > .notice[role=\"status\"]')];if(notices.length>1)throw 0;return {{state:'ready',value:f.input.value,browse:!f.button.disabled,dirty:text(banner.querySelector('.badge'))==='Unsaved changes',notice:notices.length?text(notices[0].querySelector(':scope > span')):null,pair:{pair}}};", serde_json::to_string(CHOICES.get(usize::from(i))?.label).ok()?)
        },
        Step::PreviewPage => "return nav('Project settings');".into(),
        Step::Preview => "const b=document.querySelector('.draft-toolbar button[aria-describedby=\"draft-review-reason\"]');if(!b||b.disabled)return wait();if(text(b)!=='Review draft changes')throw 0;show(b);b.click();return ready();".into(),
        Step::Previewed => "const r=document.querySelector('.draft-review');if(!r||text(r.querySelector('.section-heading .badge'))!=='Current draft · retained baseline')return wait();show(r);if(text(r.querySelector('.review-section-heading h3'))!=='Format validation needs attention'||text(r.querySelector('.review-section-heading .badge'))!=='invalid')throw 0;return ready();".into(),
        _ => return None,
    };
    Some(format!(r#"(()=>{{try{{'use strict';
        const text=e=>(e?.textContent??'').trim().replace(/\s+/g,' '),wait=()=>({{state:'wait'}}),ready=()=>({{state:'ready'}});
        const show=e=>{{if(!e||!e.isConnected)throw 0;e.scrollIntoView({{block:'center'}});const r=e.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(e).visibility==='hidden')throw 0;}};
        if(document.querySelector('dialog[open],main > [role="alert"]'))throw 0;
        const nav=label=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+label+'"]');if(!b||b.disabled)return wait();show(b);b.click();return ready();}};
        const field=label=>{{const rows=[...document.querySelectorAll('.form-field')].filter(f=>f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: '+label);
            if(!rows.length)return null;if(rows.length!==1)throw 0;const row=rows[0],input=row.querySelector('input[type="text"]'),button=row.querySelector('button[aria-label="Browse existing '+label+'"]');
            if(!input||!button||input.value.length>512)throw 0;return {{input,button}};}};
        {body}
    }}catch{{return {{state:'error'}}}}}})()"#))
}

pub(super) fn data_checks() -> bool {
    let record = Record::new();
    if record.report(Some(false), true).is_some() || index(1).is_some() || index(12).is_some() || id(10).is_some() { return false; }
    for i in 0..COUNT as u8 {
        if id(i).and_then(index) != Some(i) || kind(i).is_none() || kind_name(i).is_none() { return false; }
        let mut record = Record::new(); record.completed = usize::from(i); record.rows[usize::from(i)].requested = true;
        let name = VersionSourceNamePreparation { result: "ok", facts: Some(31) };
        let mask = 511 | 4096 | if accepts(i) { 512 | 1024 } else { 0 };
        let file_filter = Some(if kind(i) == Some(PanelKind::VersionSource) { 55 } else { 0 });
        if record.name_preparation(i, name) || record.prepared(i) || record.name_pending(i)
            || !record.preparation(i, ProjectFieldPreparation { result: "would-block", facts: Some(0), file_filter: Some(0) }) || record.navigation_prepared(i)
            || !record.preparation(i, ProjectFieldPreparation { result: "ok", facts: Some(mask), file_filter }) || !record.navigation_prepared(i)
            || record.preparation(i, ProjectFieldPreparation { result: "ok", facts: Some(mask), file_filter }) { return false; }
        if needs_name(i) {
            if record.prepared(i) || !record.name_pending(i) { return false; }
            let mut wrong = record.clone(); wrong.completed += 1;
            if wrong.name_preparation(i, name) || wrong.name_pending(i) { return false; }
            let mut unrequested = record.clone(); unrequested.rows[usize::from(i)].requested = false;
            if unrequested.name_preparation(i, name) || unrequested.name_pending(i) { return false; }
            for flags in [None, Some(0), Some(1), Some(3), Some(7), Some(15), Some(17), Some(19), Some(23), Some(32)] {
                let mut refused = record.clone();
                if refused.name_preparation(i, VersionSourceNamePreparation { result: "ok", facts: flags })
                    || refused.prepared(i) || refused.name_pending(i)
                    || refused.name_preparation(i, name) { return false; }
            }
            for result in ["permission-denied", "io", "invalid-input", "already", "would-block", "invalid-return"] {
                let mut refused = record.clone();
                if refused.name_preparation(i, VersionSourceNamePreparation { result, facts: Some(31) })
                    || refused.prepared(i) || refused.name_pending(i)
                    || refused.name_preparation(i, name) { return false; }
            }
            if !record.name_preparation(i, name) || !record.prepared(i) || record.name_pending(i)
                || record.name_preparation(i, name) { return false; }
        } else if !record.prepared(i) || record.name_pending(i) || record.name_preparation(i, name) { return false; }
        for bit in [1, 2, 4, 8, 16, 32, 64, 128, 256, 4096] {
            if (ProjectFieldPreparation { result: "ok", facts: Some(mask & !bit), file_filter }).succeeded(kind(i).unwrap(), accepts(i)) { return false; }
        }
        if (ProjectFieldPreparation { result: "ok", facts: Some(mask | 2048), file_filter }).succeeded(kind(i).unwrap(), accepts(i)) { return false; }
    }
    true
}
