//! Two fixed nonshipping observations of the existing ToolSetup/Saved/CLI
//! owners. No supplier, cache origin, permission, native join or missing-tool
//! result is constructed here. All comparisons follow genuine returned calls.
use super::super::cli::fixture::Files;
use super::*;
use crate::{
    service_protocol::{Id, Settlement},
    service_tool_setup_protocol as tools,
};

pub(crate) const PUBLIC_SCOPE: &str = "tool-public-acquisition";
pub(crate) const PUBLIC_NAMES: [&str; 2] = [
    "tool-acquisition-cancel-in-transfer",
    "tool-acquisition-cold-warm",
];
const PARTS: [&str; 4] = ["jdk", "sdk-platform", "sdk-build-tools", "gradle"];
const ARCHIVE_BYTES: u64 = 76_857_898;
const MIN_CUT: u64 = 65_536;
const CALLS: usize = 7;
const ALLOW_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Inspect(u8),
    InspectWait(u8),
    Acquire(u8),
    AcquireWait(u8),
    CliAllow,
    CliSubmitted,
    CliActive,
    CliTerminal,
    CliChecked,
    Finish,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Finding {
    ServiceOrCatalogue,
    ColdSourcesPresent,
}
impl Finding {
    fn name(self) -> &'static str {
        match self {
            Self::ServiceOrCatalogue => "service-or-catalogue",
            Self::ColdSourcesPresent => "cold-sources-not-absent",
        }
    }
}
struct Grant {
    project: Id,
    instance: Id,
    grant: Id,
    review: Id,
    selection: tools::Review,
}
impl Grant {
    fn from_access(
        a: tools::Access,
        project: &Id,
        consent: &Id,
        selection: &tools::Review,
    ) -> Option<Self> {
        if a.validate().is_err()
            || !a.enabled
            || a.consumed
            || a.pending
            || a.unknown
            || a.remaining_ms == 0
            || a.project_id.as_ref() != Some(project)
            || a.grant_id.as_ref() != Some(consent)
            || a.review.as_ref() != Some(selection)
            || a.request_id.is_some()
            || a.status.is_some()
        {
            return None;
        }
        Some(Self {
            project: a.project_id?,
            instance: a.service_instance?,
            grant: a.grant_id?,
            review: a.review_id?,
            selection: a.review?,
        })
    }
    fn status<'a>(&self, a: &'a tools::Access, origin: &tools::Query) -> Option<&'a tools::Status> {
        if a.validate().is_err()
            || a.enabled
            || !a.consumed
            || a.unknown
            || a.remaining_ms != 0
            || a.project_id.as_ref() != Some(&self.project)
            || a.service_instance.as_ref() != Some(&self.instance)
            || a.grant_id.as_ref() != Some(&self.grant)
            || a.review_id.as_ref() != Some(&self.review)
            || a.review.as_ref() != Some(&self.selection)
            || a.request_id.as_ref() != Some(&origin.request_id)
        {
            return None;
        }
        a.status
            .as_ref()
            .filter(|s| &s.origin == origin && s.state != tools::State::Unknown)
    }
    fn retained_bytes(&self) -> Option<usize> {
        [
            self.project.retained_bytes(),
            self.instance.retained_bytes(),
            self.grant.retained_bytes(),
            self.review.retained_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)?
        .checked_add(self.selection.acquisition.as_ref()?.retained_bytes()?)
    }
}
struct Cli {
    files: Files,
    uid: u32,
    gid: u32,
    grant: Option<Grant>,
    origin: Option<tools::Query>,
    original: Option<Pair>,
    cut: Option<[u64; 7]>,
    after: Option<[u64; 7]>,
    returned: bool,
    host: Option<usize>,
}
pub(super) struct Record {
    finding: Option<Finding>,
    pub(super) source_reviewed: bool,
    cli: Option<Cli>,
}
impl Record {
    pub(super) fn new(case: Case, project: &Path, uid: u32) -> Result<Self, ()> {
        if !case.public_acquisition() {
            return Err(());
        }
        Ok(Self {
            finding: None,
            source_reviewed: false,
            cli: if case == Case::CancelInTransfer {
                Some(Cli {
                    // The same short HOME/application was selected BEFORE this
                    // capture and the first Ready/cache/native-state admission.
                    files: Files::capture_tools(project, uid)?,
                    uid,
                    gid: nix::unistd::getegid().as_raw(),
                    grant: None,
                    origin: None,
                    original: None,
                    cut: None,
                    after: None,
                    returned: false,
                    host: None,
                })
            } else {
                None
            },
        })
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        // Exact retained allocations plus the bounded fixed Allow/phase DATA
        // conversions. This is charged to the ORIGINAL observer census; not
        // a new quota or credit for another service/profile's backing.
        let mut n = std::mem::size_of::<Self>().checked_add(32 * 1024)?;
        if let Some(c) = &self.cli {
            n = n.checked_add(c.files.retained_bytes()?)?;
            if let Some(g) = &c.grant {
                n = n.checked_add(g.retained_bytes()?)?;
            }
            if let Some(q) = &c.origin {
                n = n
                    .checked_add(q.project_id.retained_bytes())?
                    .checked_add(q.service_instance.retained_bytes())?
                    .checked_add(q.request_id.retained_bytes())?;
            }
        }
        Some(n)
    }
    pub(super) fn final_originals(&self, control: &Control, r: &super::Record) -> bool {
        (!control.completed() || r.executed != control.unexecuted.load(Ordering::SeqCst))
            && !r.registered
            && !r.selected
            && if r.executed {
                self.finding.is_none()
                    && match control.case {
                        Case::ColdWarm => r.sources == [true; 4] && self.source_reviewed && self.cli.is_none(),
                        Case::CancelInTransfer => {
                            r.sources == [true, true, true, false] && !self.source_reviewed
                                && self.cli.as_ref().is_some_and(|c| {
                                    c.returned
                                        && c.files.closed()
                                        && c.original.is_some()
                                        && c.cut.is_some()
                                        && c.after.is_some()
                                })
                        }
                        _ => false,
                    }
            } else {
                control.case == Case::ColdWarm
                    && self.finding.is_some()
                    && self.cli.is_none()
                    && !self.source_reviewed
                    && r.sources[1..] == [false; 3]
            }
    }
    pub(super) fn report(&self, control: &Control, r: &super::Record) -> Option<Value> {
        if !r.normal_quit || !control.completed() || !self.final_originals(control, r) {
            return None;
        }
        let t = control.trace.try_lock().ok()?;
        let operation = |i: usize| {
            t.pairs[i].and_then(|p| std::str::from_utf8(&p.operation).ok().map(str::to_owned))
        };
        let cli = if let Some(c) = &self.cli {
            if c.host != Some(CALLS) || !c.returned || !c.files.closed() {
                return None;
            }
            let p = c.original?;
            Some(
                json!({"origin":c.origin.as_ref()?,"operationId":std::str::from_utf8(&p.operation).ok()?,
                "ownerGeneration":std::str::from_utf8(&p.generation).ok()?,"cut":c.cut?,"after":c.after?,
                "consumedPermission":true,"duplicateRefused":true,"nativeCallerHistoryReturned":true,
                "phaseOriginalsClosed":true,"hostWorkersJoined":CALLS}),
            )
        } else {
            None
        };
        Some(
            json!({"mechanism":"same-original-public-tool-acquisition-v1",
            "execution":if r.executed {"executed"}else{"not-executed-prerequisite"},
            "testResult":if !r.executed {"not-executed"}else if control.case==Case::ColdWarm {"cold-warm-source-inspected"}else{"cancelled-in-transfer"},
            "finding":self.finding.map_or("none",Finding::name),"initial":t.samples[0],"cold":t.samples[1],
            "warmInitial":t.samples[2],"warm":t.samples[3],"coldOperation":if control.case==Case::ColdWarm {operation(1)}else{None},"warmOperation":operation(3),
            "initialSdkSelected":control.case==Case::ColdWarm && r.sources[0],
            "selectedSources":if control.case==Case::ColdWarm {&r.sources[1..]}else{&r.sources[..3]},"sourceReviewed":self.source_reviewed,"cli":cli,
            "normalQuitOriginal":control.quit_id(),"normalAcquisitionEnabled":false,"protectedCopyRegistered":false,
            "selectedCatalogVerified":false,"allOriginalsSettled":true,"projectSentinelPreserved":true,"productionQualified":false}),
        )
    }
}

fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == names.len() && names.iter().all(|n| m.contains_key(*n)))
}
fn requirements(v: &Value) -> Option<&str> {
    v["requirements"]["sourcesSha256"].as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn missing_all(v: &Value) -> bool {
    v["kind"] == "tool-requirements-observation"
        && v["protectedTools"] == "none-in-supported-catalogue"
        && v["components"] == json!({"missing":PARTS,"compatible":[]})
        && requirements(v).is_some()
}
fn acquired_all(v: &Value, warm: bool) -> bool {
    v["kind"] == "staged-tool-sources"
        && v["schemaVersion"] == 2
        && v["copiedSourceComponents"] == json!([])
        && v["downloadedArchives"] == if warm { json!([]) } else { json!(PARTS) }
        && v["reusedArchives"] == if warm { json!(PARTS) } else { json!([]) }
        && v["groups"]
            == json!([
            {"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
            {"group":"sdk","components":["sdk-platform","sdk-build-tools"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
            {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}])
}
fn context(
    c: &build::Prepare,
    prior: &wire::Projection,
    hash: &str,
) -> Result<wire::Prepare, BridgeError> {
    wire::prepare(
        &json!({"projectId":c.project_id,"draftRevision":c.draft_revision,"baselineGeneration":c.baseline_generation,
        "savedConfig":c.saved_config,"action":"acquire","review":{"operationId":prior.operation_id,
            "ownerGeneration":prior.owner_generation,"requirementsSha256":hash}}),
    )
}
fn selection(c: &wire::Prepare) -> Option<tools::Review> {
    let r = c.review.as_ref()?;
    let v:tools::Review=serde_json::from_value(json!({"kind":"acquire-reviewed-missing","platform":"android",
        "draftRevision":c.draft_revision,"baselineGeneration":c.baseline_generation,"prepared":null,"sources":null,
        "acquisition":{"operationId":r.operation_id,"ownerGeneration":r.owner_generation,"requirementsSha256":r.requirements_sha256,
            "missing":["android-build-tools"],"compatible":["jdk","android-platform","gradle"]}})).ok()?;
    v.valid().then_some(v)
}
fn same_context(p: &wire::Projection, c: &build::Prepare, g: &Grant) -> bool {
    let Some(selected) = g.selection.acquisition.as_ref() else {
        return false;
    };
    p.context.valid()
        && p.context.project_id == c.project_id
        && p.context.draft_revision == c.draft_revision
        && p.context.baseline_generation == c.baseline_generation
        && p.context.saved_config.bytes == c.saved_config.bytes
        && p.context.saved_config.sha256 == c.saved_config.sha256
        && p.context.action == wire::Action::Acquire
        && p.context.review.as_ref().is_some_and(|r| {
            r.operation_id == selected.operation_id.as_str()
                && r.owner_generation == selected.owner_generation.as_str()
                && r.requirements_sha256 == selected.requirements_sha256
        })
}
fn same_operation(s: &tools::Status, p: &wire::Projection) -> bool {
    s.operation.as_ref().is_some_and(|o| {
        o.operation_id.as_str() == p.operation_id
            && o.owner_generation
                .as_ref()
                .is_some_and(|g| g.as_str() == p.owner_generation)
            && o.registration_generation.is_none()
    })
}
fn cancelled(s: &tools::Status, p: &wire::Projection) -> bool {
    s.validate().is_ok()
        && same_operation(s, p)
        && s.state == tools::State::Cancelled
        && s.settlement == Settlement::Settled
        && s.reason == tools::Reason::UserCancelled
        && s.outcome == Some(tools::Outcome::Cancelled)
        && s.result.is_none()
        && p.phase == wire::Phase::Terminal
        && !p.intent_usable
        && p.outcome == Some(wire::Outcome::Cancelled)
        && p.reason == wire::Reason::Cancelled
        && p.result.is_none()
}
fn partial(cut: &[u64; 7], after: &[u64; 7], uid: u32, gid: u32) -> bool {
    cut[..6] == after[..6]
        && cut[2] == 0o100600
        && cut[3] == u64::from(uid)
        && cut[4] == u64::from(gid)
        && cut[5] == 1
        && cut[6] >= MIN_CUT
        && cut[6] <= after[6]
        && after[6] < ARCHIVE_BYTES
}

pub(super) fn prerequisite(
    q: &Arc<Observation>,
    control: &Control,
) -> Result<Option<super::Step>, BridgeError> {
    // Only a returned known Service/census prerequisite before any native
    // Inspect/Acquire may take this branch. Cancellation never becomes a skip.
    if control.case != Case::ColdWarm || control.next.load(Ordering::SeqCst) != 0 {
        return Err(BridgeError::invalid());
    }
    let mut r = q.record().ok_or_else(BridgeError::invalid)?;
    let record = r.tool_setup.as_mut().ok_or_else(BridgeError::invalid)?;
    record
        .public
        .as_mut()
        .ok_or_else(BridgeError::invalid)?
        .finding = Some(Finding::ServiceOrCatalogue);
    Ok(Some(super::Step::Public(Step::Finish)))
}

pub(super) async fn tick(
    q: &Arc<Observation>,
    document: &DocumentBinding,
    step: Step,
) -> Result<Option<super::Step>, BridgeError> {
    let bad = BridgeError::invalid;
    let control = q
        .tool_setup
        .as_ref()
        .filter(|c| c.case.public_acquisition())
        .ok_or_else(bad)?;
    let project = q
        .record()
        .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
        .ok_or_else(bad)?;
    let saved = || {
        q.record()
            .and_then(|r| r.tool_setup.as_ref()?.context.clone())
            .ok_or_else(bad)
    };
    let current = || {
        q.record()
            .and_then(|r| r.tool_setup.as_ref()?.active.clone())
            .ok_or_else(bad)
    };
    let next = match step {
        Step::Inspect(i) => {
            if i != 0 && !(i == 2 && control.case == Case::ColdWarm) {
                return Err(bad());
            }
            let c = document.installed_tool_setup_saved(&project).await?;
            let input = wire::prepare(
                &json!({"projectId":project,"draftRevision":c.draft_revision,"baselineGeneration":c.baseline_generation,
                "savedConfig":c.saved_config,"action":"inspect","review":null}),
            )?;
            let p = document
                .prepare_tool_acquisition(input)?
                .operation
                .ok_or_else(bad)?;
            if !control.prepared(usize::from(i), &p) {
                return Err(bad());
            }
            {
                let mut r = q.record().ok_or_else(bad)?;
                let r = r.tool_setup.as_mut().ok_or_else(bad)?;
                r.context = Some(c);
                r.active = Some(p.clone());
            }
            document.start_tool_acquisition(wire::start(&json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT}))?)?;
            Some(Step::InspectWait(i))
        }
        Step::InspectWait(i) | Step::AcquireWait(i) => {
            let p = document
                .tool_acquisition_status()?
                .operation
                .ok_or_else(bad)?;
            let before = current()?;
            if p.operation_id != before.operation_id
                || p.owner_generation != before.owner_generation
                || p.context != before.context
            {
                return Err(bad());
            }
            if matches!(
                p.phase,
                wire::Phase::Starting | wire::Phase::Running | wire::Phase::Stopping
            ) {
                None
            } else {
                let sample = control.sample(usize::from(i), &p).ok_or_else(bad)?;
                let v = p.result.as_ref().ok_or_else(bad)?;
                if matches!(step, Step::InspectWait(_)) {
                    if !sample.initial() || requirements(v).is_none() {
                        return Err(bad());
                    }
                    if control.case == Case::ColdWarm && !missing_all(v) {
                        // Only the first known complete Inspect may report a
                        // real host discovery prerequisite. A warm failure is
                        // not erased as 'not executed'. No Acquire was sent.
                        if i != 0
                            || v["kind"] != "tool-requirements-observation"
                            || v["protectedTools"] != "none-in-supported-catalogue"
                        {
                            return Err(bad());
                        }
                        q.record()
                            .ok_or_else(bad)?
                            .tool_setup
                            .as_mut()
                            .ok_or_else(bad)?
                            .public
                            .as_mut()
                            .ok_or_else(bad)?
                            .finding = Some(Finding::ColdSourcesPresent);
                        Some(Step::Finish)
                    } else {
                        if control.case == Case::CancelInTransfer
                            && !super::component_result(v, false)
                        {
                            return Err(bad());
                        }
                        q.record()
                            .ok_or_else(bad)?
                            .tool_setup
                            .as_mut()
                            .ok_or_else(bad)?
                            .requirements = Some(requirements(v).ok_or_else(bad)?.to_owned());
                        Some(if control.case == Case::CancelInTransfer {
                            Step::CliAllow
                        } else {
                            Step::Acquire(i + 1)
                        })
                    }
                } else {
                    if control.case != Case::ColdWarm
                        || !sample.acquired()
                        || !acquired_all(v, i == 3)
                    {
                        return Err(bad());
                    }
                    if i == 1 {
                        Some(Step::Inspect(2))
                    } else if i == 3 {
                        let locations = document
                            .installed_tool_setup_all_locations(
                                &p.operation_id,
                                &p.owner_generation,
                            )
                            .ok_or_else(bad)?;
                        if !control.set_all(locations) {
                            return Err(bad());
                        }
                        return Ok(Some(super::Step::Choose(1)));
                    } else {
                        return Err(bad());
                    }
                }
            }
        }
        Step::Acquire(i) => {
            if control.case != Case::ColdWarm || !matches!(i, 1 | 3) {
                return Err(bad());
            }
            let hash = q
                .record()
                .and_then(|r| r.tool_setup.as_ref()?.requirements.clone())
                .ok_or_else(bad)?;
            let input = context(&saved()?, &current()?, &hash)?;
            let p = document
                .prepare_tool_acquisition(input)?
                .operation
                .ok_or_else(bad)?;
            if !control.prepared(usize::from(i), &p) {
                return Err(bad());
            }
            q.record()
                .ok_or_else(bad)?
                .tool_setup
                .as_mut()
                .ok_or_else(bad)?
                .active = Some(p.clone());
            document.start_tool_acquisition(wire::start(&json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT}))?)?;
            q.record()
                .ok_or_else(bad)?
                .tool_setup
                .as_mut()
                .ok_or_else(bad)?
                .executed = true;
            Some(Step::AcquireWait(i))
        }
        Step::CliAllow => {
            if control.case != Case::CancelInTransfer {
                return Err(bad());
            }
            let path = q
                .record()
                .and_then(|r| {
                    r.tool_setup
                        .as_ref()?
                        .public
                        .as_ref()?
                        .cli
                        .as_ref()?
                        .files
                        .application()
                        .ok()
                })
                .ok_or_else(bad)?;
            if path != control.application() {
                return Err(bad());
            }
            let checked = document.application_read_status()?;
            let read = document
                .allow_application_read(&project, checked.permission_revision, &path)
                .await?;
            if !read.enabled || read.remaining_ms == 0 || read.project_ids.len() != 1 {
                return Err(bad());
            }
            let hash = q
                .record()
                .and_then(|r| r.tool_setup.as_ref()?.requirements.clone())
                .ok_or_else(bad)?;
            let input = context(&saved()?, &current()?, &hash)?;
            let selected = selection(&input).ok_or_else(bad)?;
            let consent = Id::random().map_err(|_| bad())?;
            let raw = crate::edit_protocol::bounded(
                &json!({"consentId":consent,"projectId":project,"review":selected,
                "consentVersion":selected.kind.consent(),"doctorDraft":null,"sourceContext":input,"nativeConsent":wire::CONSENT,
                "licenseAcknowledged":false}),
                ALLOW_BYTES,
            )?;
            let access = document.allow_agent_tool_setup("main", &raw)?;
            let g = Grant::from_access(access, &read.project_ids[0], &consent, &selected)
                .ok_or_else(bad)?;
            let mut r = q.record().ok_or_else(bad)?;
            let c = r
                .tool_setup
                .as_mut()
                .ok_or_else(bad)?
                .public
                .as_mut()
                .ok_or_else(bad)?
                .cli
                .as_mut()
                .ok_or_else(bad)?;
            if c.grant.is_some() || c.origin.is_some() {
                return Err(bad());
            }
            c.files.send(&json!({"phase":"allowed","projectId":g.project,"serviceInstance":g.instance,"grantId":g.grant,"reviewId":g.review})).map_err(|_|bad())?;
            c.grant = Some(g);
            Some(Step::CliSubmitted)
        }
        Step::CliSubmitted => {
            let mut r = q.record().ok_or_else(bad)?;
            let c = r
                .tool_setup
                .as_mut()
                .ok_or_else(bad)?
                .public
                .as_mut()
                .ok_or_else(bad)?
                .cli
                .as_mut()
                .ok_or_else(bad)?;
            if let Some(v) = c.files.poll(0, "submitted").map_err(|_| bad())? {
                if !keys(&v, &["phase", "origin"]) || c.origin.is_some() {
                    return Err(bad());
                }
                let origin: tools::Query =
                    serde_json::from_value(v["origin"].clone()).map_err(|_| bad())?;
                let g = c.grant.as_ref().ok_or_else(bad)?;
                if origin.project_id != g.project || origin.service_instance != g.instance {
                    return Err(bad());
                }
                c.origin = Some(origin);
                Some(Step::CliActive)
            } else {
                None
            }
        }
        Step::CliActive => {
            let access = document.agent_tool_setup_access("main")?;
            let p = document
                .tool_acquisition_status()?
                .operation
                .ok_or_else(bad)?;
            let context = saved()?;
            let mut r = q.record().ok_or_else(bad)?;
            let parent = r.tool_setup.as_mut().ok_or_else(bad)?;
            let c = parent
                .public
                .as_mut()
                .ok_or_else(bad)?
                .cli
                .as_mut()
                .ok_or_else(bad)?;
            let g = c.grant.as_ref().ok_or_else(bad)?;
            let origin = c.origin.as_ref().ok_or_else(bad)?;
            let s = g.status(&access, origin).ok_or_else(bad)?;
            if s.operation.is_none() {
                if !matches!(s.state, tools::State::Queued | tools::State::Starting)
                    || s.reason != tools::Reason::None
                {
                    return Err(bad());
                }
                None
            } else {
                if !same_operation(s, &p)
                    || !same_context(&p, &context, g)
                    || s.reason != tools::Reason::None
                    || s.settlement != Settlement::Pending
                    || p.reason != wire::Reason::None
                    || p.outcome.is_some()
                    || p.result.is_some()
                    || !matches!(p.phase, wire::Phase::Starting | wire::Phase::Running)
                    || !control.bind_cli_original(&p)
                {
                    return Err(bad());
                }
                let pair = Pair::new(&p.operation_id, &p.owner_generation).ok_or_else(bad)?;
                if c.original.replace(pair).is_some() {
                    return Err(bad());
                }
                c.files.send(&json!({"phase":"active","origin":origin,"operationId":p.operation_id,"ownerGeneration":p.owner_generation})).map_err(|_|bad())?;
                // This is the real service-created native projection, not a
                // fabricated GUI Prepare/Start-return flag or intent.
                parent.active = Some(p);
                parent.executed = true;
                Some(Step::CliTerminal)
            }
        }
        Step::CliTerminal | Step::CliChecked => {
            let access = document.agent_tool_setup_access("main")?;
            let p = document
                .tool_acquisition_status()?
                .operation
                .ok_or_else(bad)?;
            let before = current()?;
            let context = saved()?;
            if p.operation_id != before.operation_id
                || p.owner_generation != before.owner_generation
                || p.context != before.context
            {
                return Err(bad());
            }
            let mut r = q.record().ok_or_else(bad)?;
            let c = r
                .tool_setup
                .as_mut()
                .ok_or_else(bad)?
                .public
                .as_mut()
                .ok_or_else(bad)?
                .cli
                .as_mut()
                .ok_or_else(bad)?;
            let g = c.grant.as_ref().ok_or_else(bad)?;
            let origin = c.origin.as_ref().ok_or_else(bad)?;
            let s = g.status(&access, origin).ok_or_else(bad)?;
            if !same_context(&p, &context, g) || !same_operation(s, &p) {
                return Err(bad());
            }
            if s.settlement == Settlement::Pending {
                if step != Step::CliTerminal
                    || s.state.terminal()
                    || !matches!(s.reason, tools::Reason::None | tools::Reason::UserCancelled)
                {
                    return Err(bad());
                }
                None
            } else {
                if !cancelled(s, &p)
                    || !control
                        .sample(1, &p)
                        .is_some_and(|s| s.cancelled_in_transfer())
                {
                    return Err(bad());
                }
                if step == Step::CliTerminal {
                    c.files.send(&json!({"phase":"terminal","origin":origin,"operationId":p.operation_id,"ownerGeneration":p.owner_generation})).map_err(|_|bad())?;
                    Some(Step::CliChecked)
                } else if let Some(v) = c.files.poll(1, "checked").map_err(|_| bad())? {
                    if !keys(&v, &["phase", "origin", "cut", "after"])
                        || v["origin"] != json!(origin)
                        || c.returned
                    {
                        return Err(bad());
                    }
                    let cut: [u64; 7] =
                        serde_json::from_value(v["cut"].clone()).map_err(|_| bad())?;
                    let after: [u64; 7] =
                        serde_json::from_value(v["after"].clone()).map_err(|_| bad())?;
                    if !partial(&cut, &after, c.uid, c.gid) {
                        return Err(bad());
                    }
                    c.cut = Some(cut);
                    c.after = Some(after);
                    c.files.close().map_err(|_| bad())?;
                    c.returned = true;
                    Some(Step::Finish)
                } else {
                    None
                }
            }
        }
        Step::Finish => {
            let (executed, initial_sdk) = {
                let r = q.record().ok_or_else(bad)?;
                let r = r.tool_setup.as_ref().ok_or_else(bad)?;
                if !r
                    .public
                    .as_ref()
                    .is_some_and(|p| p.final_originals(control, r))
                {
                    return Err(bad());
                }
                (r.executed, control.case==Case::ColdWarm && r.sources[0])
            };
            q.tool_verify().map_err(|_| bad())?;
            if !control.finish_public(executed, initial_sdk) {
                return Err(bad());
            }
            let mut r = q.record().ok_or_else(bad)?;
            if r.step != OuterStep::ToolSetup(super::Step::Public(step)) || r.pending.is_some() {
                return Err(bad());
            }
            r.file_readback = true;
            r.step = OuterStep::Close;
            None
        }
    };
    Ok(next.map(super::Step::Public))
}

impl Observation {
    pub(crate) fn tool_acquisition_cli_host_return(
        &self,
        report: &crate::application_service_host::HostShutdownReport,
    ) -> bool {
        if self.case != OuterCase::ToolSetup(Case::CancelInTransfer) {
            return false;
        }
        let Some(mut r) = self.record() else {
            return false;
        };
        let Some(c) = r
            .tool_setup
            .as_mut()
            .and_then(|t| t.public.as_mut())
            .and_then(|p| p.cli.as_mut())
        else {
            return false;
        };
        if !c.returned
            || !c.files.closed()
            || c.host.is_some()
            || !report.settled()
            || !report.failures.is_empty()
            || report.workers_joined != Some(CALLS)
        {
            self.fail_with("tool-setup-original-contract");
            return false;
        }
        c.host = report.workers_joined;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn staged(warm: bool) -> Value {
        json!({"schemaVersion":2,"kind":"staged-tool-sources","copiedSourceComponents":[],
            "downloadedArchives":if warm {json!([])}else{json!(PARTS)},"reusedArchives":if warm {json!(PARTS)}else{json!([])},
            "groups":[{"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                {"group":"sdk","components":["sdk-platform","sdk-build-tools"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}]})
    }
    #[test]
    fn public_cases_keep_old_three_and_require_complete_cold_warm_partitions() {
        assert_eq!(Case::ALL.map(Case::name), super::super::NAMES);
        assert_eq!(Case::ColdWarm.maximum_original(), 6);
        assert_eq!(Case::ColdWarm.application_prefix(), "mrk-macos-aqua-tools-public");
        for case in Case::ALL.into_iter().chain([Case::CancelInTransfer]) {
            assert_eq!(case.application_prefix(), "mrk-macos-aqua-tools");
            assert_eq!(super::super::role(case,0), Some(sources::Role::Jdk));
        }
        for (i, role) in [sources::Role::Sdk,sources::Role::Jdk,sources::Role::Sdk,sources::Role::Gradle].into_iter().enumerate() {
            assert_eq!(Case::ColdWarm.picker(i as u32+2), Some(i as u8));
            assert_eq!(super::super::role(Case::ColdWarm,i as u8), Some(role));
        }
        assert_eq!(Case::ColdWarm.picker(6),None);
        assert_eq!(Case::ColdWarm.public_quit(true,true),Some(6));
        assert_eq!(Case::ColdWarm.public_quit(false,true),Some(3));
        assert_eq!(Case::ColdWarm.public_quit(false,false),Some(2));
        assert_eq!(Case::ColdWarm.public_quit(true,false),None);
        assert_eq!(Case::CancelInTransfer.public_quit(true,false),Some(5));
        assert_eq!(Case::CancelInTransfer.public_quit(true,true),None);
        assert_eq!(Case::CancelInTransfer.maximum_original(), 5);
        assert_eq!(Case::ColdWarm.seconds(), 2400);
        assert_eq!(
            Case::parse(std::ffi::OsStr::new(PUBLIC_NAMES[0])),
            Some(Case::CancelInTransfer)
        );
        assert_eq!(
            Case::parse(std::ffi::OsStr::new(PUBLIC_NAMES[1])),
            Some(Case::ColdWarm)
        );
        for warm in [false, true] {
            let base = staged(warm);
            assert!(acquired_all(&base, warm));
            assert!(!acquired_all(&base, !warm));
            for (key, value) in [
                ("schemaVersion", json!(1)),
                ("copiedSourceComponents", json!(["sdk-platform"])),
                ("downloadedArchives", json!(["sdk-build-tools"])),
                ("reusedArchives", json!(["jdk"])),
            ] {
                let mut other = base.clone();
                other[key] = value;
                assert!(!acquired_all(&other, warm));
            }
            let mut other = base;
            other["groups"][1]["allRequiredComponentsStaged"] = json!(false);
            assert!(!acquired_all(&other, warm));
        }
        let mut observed = json!({"kind":"tool-requirements-observation","protectedTools":"none-in-supported-catalogue",
            "components":{"missing":PARTS,"compatible":[]},"requirements":{"sourcesSha256":"b".repeat(64)}});
        assert!(missing_all(&observed));
        observed["components"] =
            json!({"missing":["sdk-build-tools"],"compatible":["jdk","sdk-platform","gradle"]});
        assert!(!missing_all(&observed));
        assert!(super::super::component_result(&observed, false));
    }
    #[test]
    fn in_transfer_cut_requires_same_file_nonshrinking_partial_after_real_return() {
        let original = [10, 20, 0o100600, 501, 20, 1, MIN_CUT];
        let mut after = original;
        after[6] += MIN_CUT;
        assert!(partial(&original, &after, 501, 20));
        assert!(partial(&original, &original, 501, 20));
        for i in 0..6 {
            let mut changed = after;
            changed[i] += 1;
            assert!(!partial(&original, &changed, 501, 20));
        }
        for size in [0, MIN_CUT - 1, ARCHIVE_BYTES, ARCHIVE_BYTES + 1] {
            let mut changed = after;
            changed[6] = size;
            assert!(!partial(&original, &changed, 501, 20));
        }
        assert!(!partial(&original, &after, 502, 20));
        assert!(!partial(&original, &after, 501, 21));
        let mut later_cut = original;
        later_cut[6] = after[6] + 1;
        assert!(!partial(&later_cut, &after, 501, 20));
    }
    #[test]
    fn cli_cancel_correlation_does_not_accept_finishing_or_foreign_originals() {
        // DATA-only comparators: no Grant is installed, Session entered or
        // native Sample/caller/history receipt manufactured by this test.
        let context=wire::prepare(&json!({"projectId":"p1","draftRevision":0,"baselineGeneration":1,
            "savedConfig":{"bytes":10,"sha256":"b".repeat(64)},"action":"acquire",
            "review":{"operationId":"1".repeat(32),"ownerGeneration":"2".repeat(32),"requirementsSha256":"c".repeat(64)}}))
            .unwrap_or_else(|_|panic!("fixed context"));
        let selected = selection(&context).expect("closed acquisition selection");
        let status:tools::Status=serde_json::from_value(json!({
            "origin":{"projectId":"6".repeat(32),"serviceInstance":"7".repeat(32),"requestId":"8".repeat(32)},
            "grantId":"9".repeat(32),"reviewId":"a".repeat(32),"revision":4,"review":selected,
            "state":"cancelled","settlement":"settled","reason":"user-cancelled","outcome":"cancelled","result":null,
            "operation":{"operationId":"4".repeat(32),"ownerGeneration":"5".repeat(32),"registrationGeneration":null}})).expect("closed service status");
        let projection = wire::Projection {
            operation_id: "4".repeat(32),
            owner_generation: "5".repeat(32),
            context,
            phase: wire::Phase::Terminal,
            intent_usable: false,
            outcome: Some(wire::Outcome::Cancelled),
            reason: wire::Reason::Cancelled,
            result: None,
        };
        assert!(cancelled(&status, &projection));
        let mut finishing = status.clone();
        finishing.state = tools::State::Finishing;
        finishing.settlement = Settlement::Pending;
        finishing.outcome = None;
        assert!(finishing.validate().is_ok());
        assert!(!cancelled(&finishing, &projection));
        let mut foreign = status.clone();
        foreign.operation.as_mut().expect("operation").operation_id =
            Id::parse(&"d".repeat(32)).expect("id");
        assert!(!cancelled(&foreign, &projection));
        let mut refused = status.clone();
        refused.outcome = Some(tools::Outcome::Refused);
        assert!(!cancelled(&refused, &projection));
        let ready = tools::Access {
            service_instance: Some(status.origin.service_instance.clone()),
            project_id: Some(status.origin.project_id.clone()),
            grant_id: Some(status.grant_id.clone()),
            review_id: Some(status.review_id.clone()),
            review: Some(selected.clone()),
            enabled: true,
            remaining_ms: 1000,
            consumed: false,
            pending: false,
            unknown: false,
            request_id: None,
            status: None,
        };
        let wrong_consent = Id::parse(&"f".repeat(32)).expect("id");
        assert!(Grant::from_access(
            ready.clone(),
            &status.origin.project_id,
            &wrong_consent,
            &selected
        )
        .is_none());
        let grant = Grant::from_access(
            ready,
            &status.origin.project_id,
            &status.grant_id,
            &selected,
        )
        .expect("DATA comparison only");
        let mut returned = tools::Access {
            service_instance: Some(status.origin.service_instance.clone()),
            project_id: Some(status.origin.project_id.clone()),
            grant_id: Some(status.grant_id.clone()),
            review_id: Some(status.review_id.clone()),
            review: Some(selected),
            enabled: false,
            remaining_ms: 0,
            consumed: true,
            pending: false,
            unknown: false,
            request_id: Some(status.origin.request_id.clone()),
            status: Some(status.clone()),
        };
        assert!(grant.status(&returned, &status.origin).is_some());
        returned.request_id = Some(Id::parse(&"e".repeat(32)).expect("id"));
        assert!(grant.status(&returned, &status.origin).is_none());
        assert_eq!(CALLS, 7);
    }
}
