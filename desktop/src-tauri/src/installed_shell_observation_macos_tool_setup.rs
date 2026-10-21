//! Fixed nonshipping journeys through the ORIGINAL tool/source/registration
//! owners. No executor, supplied inventory, replacement clock, or installer.
use super::{Case as OuterCase, DocumentBinding, Observation, Step as OuterStep};
use crate::{
    android_build_protocol as build, android_registration_app_protocol as registration,
    android_tool_sources as sources, android_toolchain_catalog as catalog, error::BridgeError,
    saved_command_owner::InstalledToolSetupSample as Sample, tool_acquisition_protocol as wire,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};

#[path = "installed_shell_observation_macos_tool_fixture.rs"]
mod fixture;
pub(super) use fixture::Fixture;
#[path = "installed_shell_observation_macos_tool_service.rs"]
mod service;

pub(crate) const SECONDS: u64 = 2400;
pub(crate) const NAMES: [&str; 3] = [
    "tool-setup-missing-sdk",
    "tool-setup-cancel-transfer",
    "tool-setup-source-drift",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    RoundTrip,
    CancelBeforeTransfer,
    SourceDrift,
    ServicePreparation,
}
impl Case {
    pub(crate) const ALL: [Self; 3] = [
        Self::RoundTrip,
        Self::CancelBeforeTransfer,
        Self::SourceDrift,
    ];
    pub(crate) fn name(self) -> &'static str {
        if self == Self::ServicePreparation { service::NAME } else { NAMES[self as usize] }
    }
    pub(crate) fn seconds(self) -> u64 {
        if self == Self::ServicePreparation { service::SECONDS } else { SECONDS }
    }
    pub(crate) fn service_only(self) -> bool {
        self == Self::ServicePreparation
    }
    pub(super) fn parse(value: &std::ffi::OsStr) -> Option<Self> {
        Self::ALL.into_iter().chain([Self::ServicePreparation]).find(|c| value == c.name())
    }
    pub(crate) fn maximum_original(self) -> u32 {
        if self.service_only() {
            2
        } else if self == Self::RoundTrip {
            6
        } else {
            5
        }
    }
    pub(crate) fn picker(self, id: u32) -> Option<u8> {
        if self.service_only() { return None; }
        id.checked_sub(2)
            .and_then(|n| u8::try_from(n).ok())
            .filter(|n| *n < if self == Self::RoundTrip { 4 } else { 3 })
    }
}
pub(crate) fn role(index: u8) -> Option<sources::Role> {
    [
        sources::Role::Jdk,
        sources::Role::Sdk,
        sources::Role::Gradle,
        sources::Role::Sdk,
    ]
    .get(usize::from(index))
    .copied()
}
pub(super) fn kind(index: u8) -> Option<mrk_macos_installed_native::PanelKind> {
    use mrk_macos_installed_native::PanelKind as K;
    [
        K::AndroidJdk,
        K::AndroidSdk,
        K::AndroidGradle,
        K::AndroidSdk,
    ]
    .get(usize::from(index))
    .copied()
}
pub(super) fn kind_name(index: u8) -> Option<&'static str> {
    [
        "android-jdk",
        "android-sdk",
        "android-gradle",
        "android-sdk",
    ]
    .get(usize::from(index))
    .copied()
}
fn tuple() -> Option<(&'static str, &'static str, &'static str)> {
    let values = (
        option_env!("GITHUB_SHA")?,
        option_env!("GITHUB_RUN_ID")?,
        option_env!("GITHUB_RUN_ATTEMPT")?,
    );
    let decimal = |s: &str| {
        !s.is_empty()
            && s.len() <= 20
            && !s.starts_with('0')
            && s.bytes().all(|b| b.is_ascii_digit())
    };
    (values.0.len() == 40
        && values
            .0
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && decimal(values.1)
        && decimal(values.2))
    .then_some(values)
}
fn sources_root(home: &Path) -> Option<PathBuf> {
    let (source, run, attempt) = tuple()?;
    if !crate::asset_session::installed_macos_selection_path_bounded(home) || home == Path::new("/") {
        return None;
    }
    Some(home.join("Library/Application Support").join(format!(
        "mrk-macos-tool-inputs-{source}-{run}-{attempt}"
    )))
}
pub(super) fn fixture_root(home: &Path, case: Case) -> Option<PathBuf> {
    let (source, run, attempt) = tuple()?;
    if !crate::asset_session::installed_macos_selection_path_bounded(home) || home == Path::new("/") {
        return None;
    }
    let suffix = if case.service_only() { service::NAME } else { "tool-setup" };
    Some(home.join("Library/Application Support").join(format!(
        "mrk-macos-aqua-{source}-{run}-{attempt}-{suffix}"
    )))
}
fn application_root(home: &Path, case: Case) -> Option<PathBuf> {
    let (source, run, attempt) = tuple()?;
    if !crate::asset_session::installed_macos_selection_path_bounded(home) || home == Path::new("/")
    {
        return None;
    }
    Some(
        home.join("Library/Application Support")
            .join(format!("mrk-macos-aqua-tools-{source}-{run}-{attempt}"))
            .join(case.name())
            .join("dev.mobile-release-kit.desktop"),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pair {
    operation: [u8; 32],
    generation: [u8; 32],
}
impl Pair {
    fn new(operation: &str, generation: &str) -> Option<Self> {
        if !crate::edit_protocol::token(operation) || !crate::edit_protocol::token(generation) {
            return None;
        }
        Some(Self {
            operation: operation.as_bytes().try_into().ok()?,
            generation: generation.as_bytes().try_into().ok()?,
        })
    }
    fn matches(self, operation: &str, generation: &str) -> bool {
        operation.as_bytes() == self.operation && generation.as_bytes() == self.generation
    }
}
#[derive(Default)]
struct Trace {
    pairs: [Option<Pair>; 3],
    samples: [Option<Sample>; 3],
}
pub(crate) struct Registration {
    control: Arc<Control>,
    document: Weak<()>,
}
pub(crate) struct Control {
    case: Case,
    project: PathBuf,
    application: PathBuf,
    inputs: [PathBuf; 3],
    acquired_sdk: OnceLock<PathBuf>,
    original: OnceLock<Weak<Observation>>,
    document: OnceLock<Weak<()>>,
    claimed: AtomicBool,
    returned: AtomicBool,
    next: AtomicU8,
    cancel: AtomicBool,
    selected: AtomicBool,
    complete: AtomicBool,
    unexecuted: AtomicBool,
    quit: AtomicU8,
    trace: Mutex<Trace>,
}
impl Control {
    pub(super) fn new(case: Case, project: &Path, uid: u32) -> Result<Arc<Self>, ()> {
        if !cfg!(target_arch = "aarch64") || uid == 0 {
            return Err(());
        }
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map_err(|_| ())?
            .ok_or(())?;
        if user.uid.as_raw() != uid {
            return Err(());
        }
        let application = application_root(&user.dir, case).ok_or(())?;
        let inputs = if case.service_only() {
            std::array::from_fn(|_| PathBuf::new())
        } else {
            let input = sources_root(&user.dir).ok_or(())?;
            let shared = input.join(Case::CancelBeforeTransfer.name());
            [shared.join("jdk/temurin-17.jdk"), input.join(case.name()).join("sdk"), shared.join("gradle")]
        };
        Ok(Arc::new(Self {
            case,
            project: project.to_path_buf(),
            application,
            inputs,
            acquired_sdk: OnceLock::new(),
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            next: AtomicU8::new(0),
            cancel: AtomicBool::new(false),
            selected: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            unexecuted: AtomicBool::new(false),
            quit: AtomicU8::new(case.maximum_original() as u8),
            trace: Mutex::new(Trace::default()),
        }))
    }
    pub(super) fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| {
            q.case == OuterCase::ToolSetup(self.case)
                && q.tool_setup
                    .as_ref()
                    .is_some_and(|c| std::ptr::eq(c.as_ref(), self))
        })
    }
    pub(crate) fn bound(&self, document: &Arc<()>) -> bool {
        self.claimed.load(Ordering::SeqCst)
            && self.returned.load(Ordering::SeqCst)
            && self
                .document
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|d| Arc::ptr_eq(&d, document))
            && self.observation().is_some()
    }
    pub(crate) fn permits(&self, document: &Arc<()>) -> bool {
        self.bound(document)
            && !self.complete.load(Ordering::SeqCst)
            && self.observation().is_some_and(|q| q.timely())
    }
    pub(crate) fn case(&self) -> Case {
        self.case
    }
    pub(crate) fn project(&self) -> &Path {
        &self.project
    }
    pub(crate) fn application(&self) -> &Path {
        &self.application
    }
    pub(crate) fn target(&self, index: u8) -> Option<&Path> {
        if self.case.service_only() { return None; }
        if index == 3 && self.case == Case::RoundTrip {
            self.acquired_sdk.get().map(PathBuf::as_path)
        } else {
            self.inputs.get(usize::from(index)).map(PathBuf::as_path)
        }
    }
    pub(crate) fn fail(&self) {
        if let Some(q) = self.observation() {
            q.fail_with("tool-setup-original-contract");
        }
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // Exact bounded backing in the existing tool census, not a new quota.
        let mut n = std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.project.capacity())?
            .checked_add(self.application.capacity())?;
        for path in &self.inputs {
            n = n.checked_add(path.capacity())?;
        }
        if let Some(path) = self.acquired_sdk.get() {
            n = n.checked_add(path.capacity())?;
        }
        drop(self.trace.try_lock().ok()?);
        let q = self.observation()?;
        let record = q.record.try_lock().ok()?;
        // The retained context/projection and the largest fixture readback
        // clone stay charged in the same original acquisition census. Failure
        // to visit exact backing refuses admission; no guessed fixed credit.
        n = n.checked_add(record.tool_setup.as_ref()?.retained_bytes()?)?;
        n = n.checked_add(
            record
                .fixture
                .tools
                .as_ref()?
                .retained_bytes()?
                .checked_mul(2)?,
        )?;
        Some(n)
    }
    pub(crate) fn claim_prepare(&self, context: &wire::Context) -> bool {
        if self.case.service_only() { return false; }
        let n = self.next.load(Ordering::SeqCst);
        if n >= if self.case == Case::RoundTrip { 3 } else { 2 }
            || context.action
                != if n == 1 {
                    wire::Action::Acquire
                } else {
                    wire::Action::Inspect
                }
            || context.draft_revision != 0
            || context.baseline_generation != 1
            || context.saved_config.bytes != super::CONFIG.len() as u32
            || context.saved_config.sha256 != super::digest(super::CONFIG)
        {
            return false;
        }
        let Ok(trace) = self.trace.try_lock() else {
            return false;
        };
        if n == 1 && !trace.samples[0].is_some_and(|s| s.initial())
            || n == 2
                && (!self.selected.load(Ordering::SeqCst)
                    || !trace.samples[1].is_some_and(|s| s.acquired()))
        {
            return false;
        }
        self.next
            .compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn prepared(&self, index: usize, projection: &wire::Projection) -> bool {
        let Some(pair) = Pair::new(&projection.operation_id, &projection.owner_generation) else {
            return false;
        };
        let Ok(mut trace) = self.trace.try_lock() else {
            return false;
        };
        if index >= 3
            || self.next.load(Ordering::SeqCst) != index as u8 + 1
            || trace.pairs[index].is_some()
            || projection.phase != wire::Phase::AwaitingConsent
            || !projection.intent_usable
            || projection.outcome.is_some()
            || projection.reason != wire::Reason::None
            || projection.result.is_some()
        {
            return false;
        }
        trace.pairs[index] = Some(pair);
        true
    }
    pub(crate) fn cancel_checkpoint(&self, operation: &str, generation: &str) -> bool {
        self.case == Case::CancelBeforeTransfer
            && self.next.load(Ordering::SeqCst) == 2
            && self.trace.try_lock().is_ok_and(|trace| {
                trace.pairs[1].is_some_and(|p| p.matches(operation, generation))
                    && trace.samples[0].is_some_and(|s| s.initial())
                    && trace.samples[1].is_none()
            })
            && !self.cancel.swap(true, Ordering::SeqCst)
    }
    pub(crate) fn record(&self, sample: Sample) {
        let result = (|| {
            let mut trace = self.trace.try_lock().ok()?;
            let index = trace.pairs.iter().position(|pair| {
                pair.is_some_and(|p| sample.same_operation(&p.operation, &p.generation))
            })?;
            if trace.samples[index].is_some() {
                return None;
            }
            trace.samples[index] = Some(sample);
            Some(())
        })();
        if result.is_none() {
            self.fail();
        }
    }
    fn sample(&self, index: usize, projection: &wire::Projection) -> Option<Sample> {
        self.trace
            .try_lock()
            .ok()?
            .samples
            .get(index)
            .copied()
            .flatten()
            .filter(|sample| sample.matches(projection))
    }
    fn set_sdk(&self, path: PathBuf) -> bool {
        self.case == Case::RoundTrip
            && crate::tool_acquisition_protocol::native_path(&path).is_some()
            && self.acquired_sdk.set(path).is_ok()
    }
    pub(crate) fn quit_id(&self) -> u32 {
        u32::from(self.quit.load(Ordering::SeqCst))
    }
    pub(crate) fn completed(&self) -> bool {
        self.complete.load(Ordering::SeqCst)
    }
    fn finish(&self, executed: bool) -> bool {
        if self.case.service_only() { return false; }
        let Ok(trace) = self.trace.try_lock() else {
            return false;
        };
        if if executed {
            !trace.samples[0].is_some_and(|s| s.initial())
                || match self.case {
                    Case::RoundTrip => {
                        !trace.samples[1].is_some_and(|s| s.acquired())
                            || !trace.samples[2].is_some_and(|s| s.reused())
                    }
                    Case::CancelBeforeTransfer => {
                        !self.cancel.load(Ordering::SeqCst)
                            || !trace.samples[1].is_some_and(|s| s.cancelled_before_transfer())
                    }
                    Case::SourceDrift => !trace.samples[1].is_some_and(|s| s.refused_source()),
                    Case::ServicePreparation => true,
                }
        } else {
            self.next.load(Ordering::SeqCst) != 0 || trace.samples.iter().any(Option::is_some)
        } {
            return false;
        }
        if self.complete.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.unexecuted.store(!executed, Ordering::SeqCst);
        self.quit.store(
            if executed {
                self.case.maximum_original() as u8
            } else {
                2
            },
            Ordering::SeqCst,
        );
        true
    }
    fn finish_service(&self, ready: bool) -> bool {
        let Ok(trace) = self.trace.try_lock() else { return false; };
        if !self.case.service_only() || self.next.load(Ordering::SeqCst) != 0
            || trace.pairs.iter().any(Option::is_some) || trace.samples.iter().any(Option::is_some)
            || self.complete.swap(true, Ordering::SeqCst) { return false; }
        self.unexecuted.store(!ready, Ordering::SeqCst);
        self.quit.store(2, Ordering::SeqCst);
        true
    }
    fn attach(
        self: &Arc<Self>,
        q: &Arc<Observation>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if q.case != OuterCase::ToolSetup(self.case)
            || std::thread::current().id() != q.main
            || !q.timely()
        {
            return Err(BridgeError::invalid());
        }
        let identity = document.installed_macos_project_fields_identity();
        if self.original.set(Arc::downgrade(q)).is_err()
            || self.document.set(identity.clone()).is_err()
        {
            return Err(BridgeError::invalid());
        }
        document.register_installed_macos_tool_setup(Registration {
            control: self.clone(),
            document: identity,
        })?;
        if self.returned.swap(true, Ordering::SeqCst) {
            return Err(BridgeError::invalid());
        }
        Ok(())
    }
}
impl Registration {
    pub(crate) fn consume(self, document: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        let q = self
            .control
            .observation()
            .ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !r.attached
            || r.started
            || r.loaded
            || !q.timely()
            || !self
                .document
                .upgrade()
                .is_some_and(|d| Arc::ptr_eq(&d, document))
            || self.control.claimed.swap(true, Ordering::SeqCst)
        {
            return Err(BridgeError::invalid());
        }
        drop(r);
        Ok(self.control)
    }
}
impl Observation {
    /// `Some` suppresses the ordinary resolver even if this binding refuses.
    /// It is never a fallback to shipping app-data or an environment pathname.
    pub(crate) fn tool_setup_application(&self) -> Option<&Path> {
        self.tool_setup.as_ref().map(|c| c.application())
    }
    pub(crate) fn attach_tool_setup(
        self: &Arc<Self>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if let Some(control) = &self.tool_setup {
            control.attach(self, document)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Context,
    Prerequisite(service::Step),
    Service,
    ServiceWait,
    Catalog,
    CatalogWait,
    Choose(u8),
    Native(u8),
    Chosen(u8),
    Inspect,
    InspectWait,
    Acquire,
    AcquireWait,
    RegisterInspect,
    RegisterReview,
    Register,
    Registered,
    Recover,
    Recovered,
    Select,
    Reuse,
    ReuseWait,
    Finish,
}
#[derive(Default)]
pub(super) struct Record {
    service: service::Record,
    context: Option<build::Prepare>,
    active: Option<wire::Projection>,
    requirements: Option<String>,
    source_generation: u32,
    registration_generation: u32,
    review_id: Option<String>,
    service_operation: Option<String>,
    registered: bool,
    selected: bool,
    executed: bool,
    sources: [bool; 4],
    normal_quit: bool,
    pub(super) attached: [bool; 4],
    pub(super) actions: [bool; 4],
}
impl Record {
    fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>().checked_add(self.service.retained_bytes()?)?;
        if let Some(context) = &self.context {
            n = n.checked_add(context.retained_heap_bytes()?)?;
        }
        for value in [&self.requirements, &self.review_id, &self.service_operation]
            .into_iter()
            .flatten()
        {
            n = n.checked_add(value.capacity())?;
        }
        if let Some(p) = &self.active {
            // Only the original AwaitingConsent projection is retained here;
            // completed result trees stay with the original SavedOwner.
            if p.result.is_some() {
                return None;
            }
            for value in [
                &p.operation_id,
                &p.owner_generation,
                &p.context.project_id,
                &p.context.saved_config.sha256,
            ] {
                n = n.checked_add(value.capacity())?;
            }
            if let Some(review) = &p.context.review {
                for value in [
                    &review.operation_id,
                    &review.owner_generation,
                    &review.requirements_sha256,
                ] {
                    n = n.checked_add(value.capacity())?;
                }
            }
        }
        Some(n)
    }
    pub(super) fn report(&self, control: &Control) -> Option<Value> {
        if control.case.service_only() { return self.service.report(control, self.normal_quit); }
        if !control.completed()
            || !self.normal_quit
            || self.executed == control.unexecuted.load(Ordering::SeqCst)
        {
            return None;
        }
        let trace = control.trace.try_lock().ok()?;
        Some(
            json!({"mechanism":"same-original-tool-setup-v1","normalAcquisitionEnabled":false,
            "execution":if self.executed {"executed"} else {"not-executed-prerequisite"},
            "testResult":if !self.executed {"not-executed"} else {match control.case {Case::RoundTrip=>"registered-reused",Case::CancelBeforeTransfer=>"cancelled-before-transfer",Case::SourceDrift=>"source-refused-before-effects",Case::ServicePreparation=>return None}},
            "initial":trace.samples[0],"acquire":trace.samples[1],"reuse":trace.samples[2],
            "selectedSources":self.sources,"protectedCopyRegistered":self.registered,"selectedCatalogVerified":self.selected,
            "normalQuitOriginal":control.quit_id(),"allOriginalsSettled":true,"projectSentinelPreserved":true,
            "automaticRegistration":false,"privilegedInstallRequested":false,"productionQualified":false,
            "pendingCaseReused":false,"retirement":"retain-task-owned-cache-and-source-until-original-host-retirement"}),
        )
    }
    pub(super) fn final_originals(&mut self, control: &Control, quit: u32, finality: bool) -> bool {
        if control.case.service_only() {
            if self.normal_quit || !control.completed() || quit!=2 || !finality
                || self.sources != [false;4] || self.registered || self.selected || self.executed
                || self.active.is_some() || self.requirements.is_some() || self.review_id.is_some() {
                return false;
            }
            self.normal_quit=true;
            return self.service.report(control,true).is_some();
        }
        if self.normal_quit
            || !control.completed()
            || !finality
            || quit != control.quit_id()
            || if self.executed {
                self.sources
                    != if control.case == Case::RoundTrip {
                        [true; 4]
                    } else {
                        [true, true, true, false]
                    }
                    || self.registered != (control.case == Case::RoundTrip)
                    || self.selected != self.registered
            } else {
                self.sources != [false; 4] || self.registered || self.selected
            }
        {
            return false;
        }
        self.normal_quit = true;
        true
    }
}

fn registration_pending(phase: registration::Phase) -> bool {
    matches!(
        phase,
        registration::Phase::Inspecting
            | registration::Phase::Preparing
            | registration::Phase::Copying
            | registration::Phase::Verifying
            | registration::Phase::Publishing
            | registration::Phase::Settling
    )
}
fn compatible_sources(sources: &[registration::Source]) -> bool {
    sources.len() == 3
        && sources
            .iter()
            .zip([
                sources::Role::Jdk,
                sources::Role::Sdk,
                sources::Role::Gradle,
            ])
            .all(|(s, r)| {
                s.role == r
                    && s.complete
                    && s.compatibility == registration::Compatibility::Compatible
            })
}
fn comparison(c: &catalog::Comparison) -> catalog::Compare {
    catalog::Compare {
        schema_version: 1,
        catalog_generation: c.catalog_generation,
        instance: c.instance.clone(),
        record_sha256: c.record_sha256.clone(),
        inventory_sha256: c.inventory_sha256.clone(),
        os_provider_sha256: c.os_provider_sha256.clone(),
    }
}
fn component_result(value: &Value, reuse: bool) -> bool {
    value["kind"] == "tool-requirements-observation"
        && value["protectedTools"]
            == if reuse {
                "reuse-selected"
            } else {
                "none-in-supported-catalogue"
            }
        && value["components"]
            == if reuse {
                json!({"missing":[],"compatible":["jdk","sdk-platform","sdk-build-tools","gradle"]})
            } else {
                json!({"missing":["sdk-build-tools"],"compatible":["jdk","sdk-platform","gradle"]})
            }
}
fn acquired_result(value: &Value) -> bool {
    value["kind"] == "staged-tool-sources"
        && value["schemaVersion"] == 2
        && value["copiedSourceComponents"] == json!(["sdk-platform"])
        && value["downloadedArchives"] == json!(["sdk-build-tools"])
        && value["reusedArchives"] == json!([])
        && value["groups"]
            == json!([{"group":"sdk","components":["sdk-platform","sdk-build-tools"],
            "allRequiredComponentsStaged":true,"next":"choose-native-source"}])
}
impl Observation {
    /// Serial awaits stay on the existing relay. No Record/Doc/native lock
    /// crosses an await or an ordinary owner admission. A failed invoke fails
    /// this observation; it never clears/retries the original operation.
    pub(super) async fn tool_tick(
        self: &Arc<Self>,
        app: &tauri::AppHandle,
        document: &DocumentBinding,
        step: Step,
    ) {
        let Some(control) = self.tool_setup.as_ref() else {
            self.fail_with("tool-setup-original-contract");
            return;
        };
        let result: Result<Option<Step>,BridgeError> = async {
            let invalid=BridgeError::invalid;
            let project=self.record().and_then(|r|r.project.as_ref().map(|p|p.id.clone())).ok_or_else(invalid)?;
            let context=||self.record().and_then(|r|r.tool_setup.as_ref()?.context.clone()).ok_or_else(invalid);
            let current=||self.record().and_then(|r|r.tool_setup.as_ref()?.active.clone()).ok_or_else(invalid);
            Ok(match step {
                Step::Context => {
                    let c=document.installed_tool_setup_saved(&project).await?;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.context=Some(c);
                    Some(if control.case.service_only() {Step::Prerequisite(service::Step::Request)}else{Step::Service})
                },
                Step::Prerequisite(s) => service::tick(self,document,s).await?,
                Step::Service => {
                    let before=document.android_tool_service_status()?;
                    if before.operation.is_some() || before.setup_generation!=0 {return Err(invalid());}
                    let request=registration::ServiceRequest::check(&serde_json::to_vec(&json!({"schemaVersion":1,"setupGeneration":0,"context":context()?})).map_err(|_|invalid())?)?;
                    let s=document.android_tool_service_action(request)?;
                    let op=s.operation.as_ref().filter(|op|op.action==registration::ServiceAction::Check).ok_or_else(invalid)?;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.service_operation=Some(op.operation_id.clone());
                    Some(Step::ServiceWait)
                },
                Step::ServiceWait => {
                    let s=document.android_tool_service_status()?;
                    let expected=self.record().and_then(|r|r.tool_setup.as_ref()?.service_operation.clone()).ok_or_else(invalid)?;
                    let expected_context=context()?;
                    if s.operation.as_ref().is_none_or(|op|op.operation_id!=expected || op.action!=registration::ServiceAction::Check || op.context!=expected_context) {return Err(invalid());}
                    if matches!(s.phase,registration::ServicePhase::Checking|registration::ServicePhase::Settling) {None}
                    else {
                        let observed=s.observation.filter(|o|o.native_settled && !o.mutation_entered && !o.mutation_uncertain).ok_or_else(invalid)?;
                        if s.phase==registration::ServicePhase::Complete && s.reason==registration::Reason::None
                            && s.prerequisite==registration::Prerequisite::Ready && observed.state==registration::ServiceState::Enabled {Some(Step::Choose(0))}
                        else if matches!(s.phase,registration::ServicePhase::Complete|registration::ServicePhase::Refused)
                            && s.reason!=registration::Reason::CleanupUnknown {Some(Step::Finish)}
                        else {return Err(invalid());}
                    }
                },
                Step::Catalog => {document.refresh_android_toolchain_catalog()?;Some(Step::CatalogWait)},
                Step::CatalogWait => {
                    let s=document.android_toolchain_catalog_status()?;
                    if s.phase==catalog::Phase::Reading {None}
                    else if s.phase==catalog::Phase::Ready && s.reason==catalog::Reason::None && s.selected.is_none() {
                        if s.entries.is_empty() {Some(Step::Inspect)} else {Some(Step::Finish)}
                    } else {return Err(invalid());}
                },
                Step::Choose(i) => {
                    let s=document.android_tool_sources_status()?;
                    if !matches!(s.phase,sources::Phase::Idle|sources::Phase::Selected) {return Err(invalid());}
                    let mut v=json!({"schemaVersion":1,"sourceGeneration":s.source_generation,"projectId":project,"role":role(i).ok_or_else(invalid)?});
                    if i==3 {let p=current()?;v["acquired"]=json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation});}
                    let chosen=document.choose_android_tool_source(app.clone(),sources::Choose::parse(&serde_json::to_vec(&v).map_err(|_|invalid())?)?)?;
                    let op=chosen.operation.as_ref().filter(|op|op.operation_id==u32::from(i)+2 && Some(op.role)==role(i)).ok_or_else(invalid)?;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.source_generation=op.source_generation;
                    Some(Step::Native(i))
                },
                Step::Native(_) => return Err(invalid()), // Only the original main-thread picker route may act.
                Step::Chosen(i) => {
                    let s=document.android_tool_sources_status()?;
                    if matches!(s.phase,sources::Phase::Picking|sources::Phase::Checking) {None}
                    else if s.phase==sources::Phase::Selected && s.reason==sources::Reason::NotInspected
                        && s.operation.as_ref().is_some_and(|op|op.operation_id==u32::from(i)+2 && Some(op.role)==role(i))
                        && document.installed_tool_setup_source(u32::from(i)+2,role(i).ok_or_else(invalid)?) {
                        let mut r=self.record().ok_or_else(invalid)?;
                        if r.step!=OuterStep::ToolSetup(step) || !r.retain_open(u32::from(i)+2) {return Err(invalid());}
                        let record=r.tool_setup.as_mut().ok_or_else(invalid)?;
                        if record.sources[usize::from(i)] || record.source_generation!=s.source_generation {return Err(invalid());}
                        record.sources[usize::from(i)]=true;
                        Some(if i<2 {Step::Choose(i+1)} else if i==2 {Step::Catalog} else {Step::RegisterInspect})
                    } else {return Err(invalid());}
                },
                Step::Inspect|Step::Reuse => {
                    let c=document.installed_tool_setup_saved(&project).await?;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.context=Some(c.clone());
                    let input=wire::prepare(&json!({"projectId":project,"draftRevision":c.draft_revision,"baselineGeneration":c.baseline_generation,
                        "savedConfig":c.saved_config,"action":"inspect","review":null}))?;
                    let p=document.prepare_tool_acquisition(input)?.operation.ok_or_else(invalid)?;
                    if !control.prepared(if step==Step::Inspect {0}else{2},&p) {return Err(invalid());}
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.active=Some(p.clone());
                    document.start_tool_acquisition(wire::start(&json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT}))?)?;
                    Some(if step==Step::Inspect {Step::InspectWait}else{Step::ReuseWait})
                },
                Step::InspectWait|Step::ReuseWait|Step::AcquireWait => {
                    let p=document.tool_acquisition_status()?.operation.ok_or_else(invalid)?;
                    let before=current()?;
                    if p.operation_id!=before.operation_id || p.owner_generation!=before.owner_generation || p.context!=before.context {return Err(invalid());}
                    if matches!(p.phase,wire::Phase::Starting|wire::Phase::Running|wire::Phase::Stopping) {None}
                    else {
                        let n=if step==Step::InspectWait {0}else if step==Step::AcquireWait {1}else{2};
                        let sample=control.sample(n,&p).ok_or_else(invalid)?;
                        if n==0 {
                            let v=p.result.as_ref().filter(|v|sample.initial() && component_result(v,false)).ok_or_else(invalid)?;
                            let hash=v["requirements"]["sourcesSha256"].as_str().filter(|s|(s.len()==64 && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))).ok_or_else(invalid)?;
                            self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.requirements=Some(hash.into());
                            Some(Step::Acquire)
                        } else if n==2 {
                            if !sample.reused() || !p.result.as_ref().is_some_and(|v|component_result(v,true)) {return Err(invalid());}
                            Some(Step::Finish)
                        } else if control.case==Case::RoundTrip {
                            if !sample.acquired() || !p.result.as_ref().is_some_and(acquired_result) {return Err(invalid());}
                            let path=document.installed_tool_setup_sdk_location(&p.operation_id,&p.owner_generation).ok_or_else(invalid)?;
                            if !control.set_sdk(path) {return Err(invalid());}
                            Some(Step::Choose(3))
                        } else {
                            if !(if control.case==Case::CancelBeforeTransfer {sample.cancelled_before_transfer()}else{sample.refused_source()}) {return Err(invalid());}
                            Some(Step::Finish)
                        }
                    }
                },
                Step::Acquire => {
                    if control.case==Case::SourceDrift {self.tool_drift().map_err(|_|invalid())?;}
                    let c=context()?;let prior=current()?;
                    let hash=self.record().and_then(|r|r.tool_setup.as_ref()?.requirements.clone()).ok_or_else(invalid)?;
                    // SAME saved observation/initial review; never refresh the
                    // saved lane between Inspect and its exact Acquire.
                    let input=wire::prepare(&json!({"projectId":project,"draftRevision":c.draft_revision,"baselineGeneration":c.baseline_generation,
                        "savedConfig":c.saved_config,"action":"acquire","review":{"operationId":prior.operation_id,"ownerGeneration":prior.owner_generation,"requirementsSha256":hash}}))?;
                    let p=document.prepare_tool_acquisition(input)?.operation.ok_or_else(invalid)?;
                    if !control.prepared(1,&p) {return Err(invalid());}
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.active=Some(p.clone());
                    document.start_tool_acquisition(wire::start(&json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT}))?)?;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.executed=true;
                    Some(Step::AcquireWait)
                },
                Step::RegisterInspect => {
                    let c=document.installed_tool_setup_saved(&project).await?;
                    let generation=document.android_tool_registration_status()?.registration_generation;
                    let source=document.android_tool_sources_status()?.source_generation;
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.context=Some(c.clone());
                    document.inspect_android_tool_sources(registration::Inspect{registration_generation:generation,source_generation:source,context:c})?;
                    Some(Step::RegisterReview)
                },
                Step::RegisterReview => {
                    let s=document.android_tool_registration_status()?;
                    if registration_pending(s.phase) {None}
                    else if s.phase==registration::Phase::Review && s.reason==registration::Reason::None && s.prerequisite==registration::Prerequisite::Ready {
                        let expected=context()?;
                        let review=s.review.as_ref().filter(|r|r.context==expected && r.consent_version==registration::CONSENT && r.license_acknowledgment_required).ok_or_else(invalid)?;
                        if !compatible_sources(&review.sources) {return Err(invalid());}
                        let mut r=self.record().ok_or_else(invalid)?;let v=r.tool_setup.as_mut().ok_or_else(invalid)?;
                        v.registration_generation=s.registration_generation;v.source_generation=review.source_generation;v.review_id=Some(review.review_id.clone());
                        Some(Step::Register)
                    } else {return Err(invalid());}
                },
                Step::Register => {
                    let v={let r=self.record().ok_or_else(invalid)?;let v=r.tool_setup.as_ref().ok_or_else(invalid)?;
                        json!({"schemaVersion":1,"registrationGeneration":v.registration_generation,"sourceGeneration":v.source_generation,
                            "reviewId":v.review_id,"context":v.context,"consentVersion":registration::CONSENT,"licenseAcknowledged":true})};
                    document.register_android_tool_sources(registration::Register::parse(&serde_json::to_vec(&v).map_err(|_|invalid())?)?)?;
                    Some(Step::Registered)
                },
                Step::Registered => {
                    let s=document.android_tool_registration_status()?;
                    if registration_pending(s.phase) {None}
                    else if s.phase==registration::Phase::Complete && s.reason==registration::Reason::None
                        && s.report.as_ref().is_some_and(|r|compatible_sources(&r.sources) && r.problems.recorded==0 && r.accounting.as_ref().is_some_and(|a|a.complete) && r.protected_copy==registration::ProtectedCopy::Published) {
                        self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.registered=true;
                        document.refresh_android_toolchain_catalog()?;Some(Step::Recover)
                    } else {return Err(invalid());}
                },
                Step::Recover => {
                    let s=document.android_toolchain_catalog_status()?;
                    if s.phase==catalog::Phase::Reading {None}
                    else if s.phase==catalog::Phase::Ready && s.reason==catalog::Reason::None && s.selected.is_none() && s.entries.len()==1 {
                        let row=&s.entries[0];if row.status!=catalog::RowStatus::RecoveryRequired || !row.valid(s.catalog_generation) {return Err(invalid());}
                        document.recover_android_toolchain(comparison(row.recovery.as_ref().ok_or_else(invalid)?))?;Some(Step::Recovered)
                    } else {return Err(invalid());}
                },
                Step::Recovered => {
                    let s=document.android_toolchain_catalog_status()?;
                    if s.phase==catalog::Phase::Reading {None}
                    else if s.phase==catalog::Phase::Ready && s.reason==catalog::Reason::None && s.entries.len()==1
                        && s.entries[0].status==catalog::RowStatus::VerifiedThisSession && s.entries[0].valid(s.catalog_generation) {Some(Step::Select)}
                    else {return Err(invalid());}
                },
                Step::Select => {
                    let s=document.android_toolchain_catalog_status()?;
                    if s.phase!=catalog::Phase::Ready || s.entries.len()!=1 {return Err(invalid());}
                    let row=&s.entries[0];if row.status!=catalog::RowStatus::VerifiedThisSession || !row.valid(s.catalog_generation) {return Err(invalid());}
                    let selected=row.selection.as_ref().ok_or_else(invalid)?;
                    let after=document.select_android_toolchain(comparison(&catalog::Comparison::of(selected)))?;
                    if after.selected.as_ref()!=Some(selected) {return Err(invalid());}
                    control.selected.store(true,Ordering::SeqCst);
                    self.record().ok_or_else(invalid)?.tool_setup.as_mut().ok_or_else(invalid)?.selected=true;
                    Some(Step::Reuse)
                },
                Step::Finish => {
                    let executed=self.record().and_then(|r|r.tool_setup.as_ref().map(|v|v.executed)).ok_or_else(invalid)?;
                    self.tool_verify().map_err(|_|invalid())?;
                    if !control.finish(executed) {return Err(invalid());}
                    let mut r=self.record().ok_or_else(invalid)?;
                    if r.step!=OuterStep::ToolSetup(step) || r.pending.is_some() {return Err(invalid());}
                    r.file_readback=true;r.step=OuterStep::Close;None
                },
            })
        }.await;
        match result {
            Ok(Some(next)) if self.timely() => {
                let Some(mut r) = self.record() else {
                    return;
                };
                if r.step != OuterStep::ToolSetup(step) || r.pending.is_some() {
                    self.fail_with("tool-setup-original-contract");
                    return;
                }
                r.step = OuterStep::ToolSetup(next);
            }
            Ok(None) => {}
            _ => self.fail_with("tool-setup-original-contract"),
        }
    }
}

pub(super) fn service_data_checks() -> bool { service::data_checks() }
