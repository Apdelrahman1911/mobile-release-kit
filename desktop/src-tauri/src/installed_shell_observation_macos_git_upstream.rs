//! One fixed local SetUpstream journey in the existing installed observer.
//! This comparison control grants no runtime/profile, Connection, source,
//! Candidate/ACK or finality authority. All five Git calls use ordinary owners.
use super::{Case as OuterCase, DocumentBinding, GitReadCheck as ReadCheck, GitReadFailureSample, Observation, Step as OuterStep};
use crate::{
    error::BridgeError, git_local_protocol as local, git_read_protocol as read,
    git_upstream_protocol as upstream,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock, Weak,
    },
};
#[path = "installed_shell_observation_macos_git_upstream_fixture.rs"]
mod fixture;
pub(super) use fixture::Fixture;
pub(crate) const NAME: &str = "git-upstream-local";
pub(crate) const SECONDS: u64 = 120;
const REPOSITORY: &str = "mrk-upstream-fixture/local";
fn tuple() -> Option<(&'static str, &'static str, &'static str)> {
    let t = (
        option_env!("GITHUB_SHA")?,
        option_env!("GITHUB_RUN_ID")?,
        option_env!("GITHUB_RUN_ATTEMPT")?,
    );
    let decimal = |s: &str| {
        !s.is_empty()
            && s.len() <= 20
            && !s.starts_with('0')
            && s.bytes().all(|c| c.is_ascii_digit())
    };
    (crate::git_fetch_protocol::oid(t.0) && decimal(t.1) && decimal(t.2)).then_some(t)
}
fn support(home: &Path) -> Option<PathBuf> {
    (home != Path::new("/") && crate::asset_session::installed_macos_selection_path_bounded(home))
        .then(|| home.join("Library/Application Support"))
}
pub(super) fn fixture_root(home: &Path) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    Some(support(home)?.join(format!("mrk-macos-aqua-{s}-{r}-{a}-git-upstream-native")))
}
fn application_root(home: &Path) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    Some(
        support(home)?
            .join(format!("mrk-macos-aqua-upstream-{s}-{r}-{a}"))
            .join(NAME)
            .join("dev.mobile-release-kit.desktop"),
    )
}
pub(crate) struct Registration {
    control: Arc<Control>,
    document: Weak<()>,
}
pub(crate) struct Control {
    project: PathBuf,
    application: PathBuf,
    original: OnceLock<Weak<Observation>>,
    document: OnceLock<Weak<()>>,
    claimed: AtomicBool,
    returned: AtomicBool,
    complete: AtomicBool,
}
impl Control {
    pub(super) fn new(project: &Path, uid: u32) -> Result<Arc<Self>, ()> {
        if !cfg!(target_arch = "aarch64") || uid == 0 {
            return Err(());
        }
        let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map_err(|_| ())?
            .ok_or(())?;
        if u.uid.as_raw() != uid || project != fixture_root(&u.dir).ok_or(())?.join(NAME) {
            return Err(());
        }
        Ok(Arc::new(Self {
            project: project.to_owned(),
            application: application_root(&u.dir).ok_or(())?,
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            complete: AtomicBool::new(false),
        }))
    }
    fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| {
            q.case == OuterCase::GitUpstream
                && q.git_upstream
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
    fn live(&self) -> bool {
        self.document
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|d| self.bound(&d))
            && !self.completed()
            && self.observation().is_some_and(|q| q.timely())
    }
    pub(crate) fn project(&self) -> &Path {
        &self.project
    }
    pub(crate) fn application(&self) -> &Path {
        &self.application
    }
    pub(crate) fn completed(&self) -> bool {
        self.complete.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // Fixed independent <=64KiB reads, bounded comparisons/temporary clones,
        // and original projections. Added to the SAME complete Document census;
        // no native slot, history or working-reservation credit is taken.
        let n = std::mem::size_of::<Self>()
            .checked_add(1024 * 1024)?
            .checked_add(self.project.capacity())?
            .checked_add(self.application.capacity())?
            .checked_add(4 * std::mem::size_of::<usize>())?;
        let q = self.observation()?;
        let r = q.record.try_lock().ok()?;
        n.checked_add(r.git_upstream.as_ref()?.retained_bytes()?)?
            .checked_add(
                r.fixture
                    .git_upstream
                    .as_ref()?
                    .retained_bytes()?
                    .checked_mul(2)?,
            )
    }
    fn finish(&self, r: &Record) -> bool {
        self.live()
            && r.read_count == 2
            && r.prepare_count == 2
            && r.applied
            && r.closed
            && r.after.is_some()
            && !r.normal_quit
            && !self.complete.swap(true, Ordering::SeqCst)
    }
    fn attach(
        self: &Arc<Self>,
        q: &Arc<Observation>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if q.case != OuterCase::GitUpstream || std::thread::current().id() != q.main || !q.timely()
        {
            return Err(BridgeError::invalid());
        }
        let identity = document.installed_macos_project_fields_identity();
        self.original
            .set(Arc::downgrade(q))
            .map_err(|_| BridgeError::invalid())?;
        self.document
            .set(identity.clone())
            .map_err(|_| BridgeError::invalid())?;
        document.register_installed_macos_git_upstream(Registration {
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
    pub(crate) fn git_upstream_application(&self) -> Option<&Path> {
        self.git_upstream.as_ref().map(|c| c.application())
    }
    pub(crate) fn attach_git_upstream(
        self: &Arc<Self>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if let Some(c) = &self.git_upstream {
            c.attach(self, document)?
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Read,
    ReadWait,
    Prepare,
    PrepareWait,
    Apply,
    ApplyWait,
    CloseReview,
    Finish,
}
#[derive(Clone)]
struct ReadOriginal {
    id: String,
    context: read::Context,
    action: read::Action,
}
impl ReadOriginal {
    fn capture(p: &read::Projection) -> Self {
        Self {
            id: p.operation_id.clone(),
            context: p.context.clone(),
            action: p.action.clone(),
        }
    }
    fn matches(&self, p: &read::Projection) -> bool {
        self.id == p.operation_id && self.context == p.context && self.action == p.action
    }
}
#[derive(Clone)]
struct LocalOriginal {
    id: String,
    context: local::Context,
    phase: local::Phase,
    action: local::PublicAction,
}
impl LocalOriginal {
    fn capture(p: &local::Projection) -> Self {
        Self {
            id: p.operation_id.clone(),
            context: p.context.clone(),
            phase: p.phase,
            action: p.action.clone(),
        }
    }
    fn matches(&self, p: &local::Projection) -> bool {
        self.id == p.operation_id
            && self.context == p.context
            && self.phase == p.phase
            && self.action == p.action
    }
}
#[derive(Default)]
pub(super) struct Record {
    reads: Vec<ReadOriginal>,
    locals: Vec<LocalOriginal>,
    action: Option<upstream::Action>,
    prepared: Option<local::Prepared>,
    revision: Option<String>,
    reference_revision: Option<String>,
    after: Option<fixture::After>,
    read_count: u8,
    prepare_count: u8,
    applied: bool,
    closed: bool,
    normal_quit: bool,
}
impl Record {
    fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>()
            .checked_add(2 * local::REVIEW_BACKING)?
            .checked_add(
                self.reads
                    .capacity()
                    .checked_mul(std::mem::size_of::<ReadOriginal>())?,
            )?
            .checked_add(
                self.locals
                    .capacity()
                    .checked_mul(std::mem::size_of::<LocalOriginal>())?,
            )?;
        for p in &self.reads {
            for s in [&p.id, &p.context.project_id, &p.context.revision] {
                n = n.checked_add(s.capacity())?;
            }
        }
        for s in [&self.revision, &self.reference_revision]
            .into_iter()
            .flatten()
        {
            n = n.checked_add(s.capacity())?;
        }
        if let Some(a) = &self.after {
            n = n.checked_add(a.retained_bytes()?)?
        }
        Some(n)
    }
    pub(super) fn final_originals(&mut self, c: &Control, id: u32, finality: bool) -> bool {
        if self.normal_quit
            || !c.completed()
            || !finality
            || id != 2
            || self.read_count != 2
            || self.prepare_count != 2
            || self.reads.len() != 2
            || self.locals.len() != 3
            || !self.applied
            || !self.closed
            || self.after.is_none()
        {
            return false;
        }
        self.normal_quit = true;
        true
    }
    pub(super) fn report(&self, c: &Control) -> Option<Value> {
        if !self.normal_quit || !c.completed() || !self.closed {
            return None;
        }
        Some(
            json!({"mechanism":"same-original-git-upstream-v1","case":NAME,"readOriginalsJoined":2,
            "prepareOriginalsJoined":2,"applyOriginalJoined":true,"unchangedReviewClosed":true,
            "normalQuitOriginal":2,"allOriginalsSettled":true,"configOnly":true,"newParentDirectories":4,
            "trackingAbsent":true,"worktreePreserved":true,"networkRequested":false,"bootstrapOverride":false,
            "productionQualified":false}),
        )
    }
}
fn same(old: Option<&LocalOriginal>, p: &local::Projection) -> bool {
    old.is_some_and(|o| o.matches(p))
}
fn settled(p: &local::Projection) -> bool {
    p.stage == read::Phase::Settled && p.outcome == Some(read::Outcome::Ok) && p.reason.is_none()
}
fn tracking(value: &Value, configured: bool) -> bool {
    let expected = if configured {
        json!({"state":"gone","remote":"origin","mergeRef":"refs/heads/main",
        "localRef":"refs/remotes/origin/main","head":null,"ahead":null,"behind":null})
    } else {
        json!({"state":"not-configured","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null})
    };
    value == &expected
}
impl Observation {
    pub(super) fn git_upstream_final_fixture_readback(&self) -> Option<()> {
        let c = self.git_upstream.as_ref()?;
        if self.case != OuterCase::GitUpstream || !c.completed() { return None; }
        let (fixture, root, uid, after) = {
            let r = self.record()?;
            let v = r.git_upstream.as_ref()?;
            if !self.final_fixture_shape(&r) || !v.normal_quit { return None; }
            (r.fixture.git_upstream.as_ref()?.clone(), r.fixture.root.clone(), r.fixture.uid, v.after.as_ref()?.clone())
        };
        if !self.timely() || fixture.verify_unchanged(&root, uid, &after).is_err() { return None; }
        let r = self.record()?;
        (self.final_fixture_shape(&r) && c.completed()
            && r.fixture.root == root && r.fixture.uid == uid
            && r.fixture.git_upstream.as_ref() == Some(&fixture)
            && r.git_upstream.as_ref().is_some_and(|v| v.normal_quit && v.after.as_ref() == Some(&after))).then_some(())
    }
    pub(super) async fn git_upstream_tick(
        self: &Arc<Self>,
        _app: &tauri::AppHandle,
        document: &DocumentBinding,
        step: Step,
    ) {
        let Some(control) = &self.git_upstream else {
            self.fail_with("git-upstream-original-contract");
            return;
        };
        let invalid = BridgeError::invalid;
        let outcome: Result<Option<Step>, BridgeError> = (|| {
            if !control.live() {
                return Err(invalid());
            }
            let project = self
                .record()
                .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
                .ok_or_else(invalid)?;
            Ok(match step {
                Step::Read => {
                    {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_upstream.as_ref().ok_or_else(invalid)?;
                        if v.read_count >= 2
                            || v.reads.len() != usize::from(v.read_count)
                            || v.applied != (v.read_count == 1)
                        {
                            return Err(invalid());
                        }
                    }
                    let started = document.git_read_start(read::Start {
                        project_id: project.clone(),
                        expected_document_revision: document.git_read_status().document_revision,
                        action: read::Action {
                            kind: read::Kind::Observe,
                            expected_revision: None,
                            paths: Vec::new(),
                            staged: false,
                        },
                    })?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    let op = started.status.operation.ok_or_else(invalid)?;
                    if op.context.project_id != project || op.action.kind != read::Kind::Observe {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                    if v.reads.iter().any(|old| old.id == op.operation_id) {
                        return Err(invalid());
                    }
                    v.reads.push(ReadOriginal::capture(&op));
                    Some(Step::ReadWait)
                }
                Step::ReadWait => {
                    let status = document.git_read_status();
                    if status.operation.is_none() {
                        self.fail_git_read_missing(OuterStep::GitUpstream(step), "git-upstream-original-contract");
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let checked = (|| {
                        let p = status.operation.as_ref().ok_or(ReadCheck::MissingOperation)?;
                        let target = r.fixture.git_upstream.as_ref().ok_or(ReadCheck::MissingFixture)?.target().to_owned();
                        let v = r.git_upstream.as_mut().ok_or(ReadCheck::MissingOriginal)?;
                        let original = v.reads.last().ok_or(ReadCheck::MissingOriginal)?;
                        if !original.matches(p) { return Err(ReadCheck::OriginalMismatch); }
                        if !super::git_read_wait_terminal(p)? { return Ok(None); }
                        if p.result["basis"] != "local-refs-no-fetch"
                            || p.result["observation"]["head"] != target
                            || p.result["observation"]["branch"] != "refs/heads/main"
                            || !tracking(&p.result["tracking"], v.applied)
                        {
                            return Err(ReadCheck::FixtureComparison);
                        }
                        v.revision = Some(
                            p.result["observation"]["revision"]
                                .as_str()
                                .filter(|s| read::digest(s))
                                .ok_or(ReadCheck::ResultSchema)?
                                .into(),
                        );
                        v.reference_revision = Some(
                            p.result["referenceRevision"]
                                .as_str()
                                .filter(|s| read::digest(s))
                                .ok_or(ReadCheck::ReferenceRevision)?
                                .into(),
                        );
                        v.read_count += 1;
                        Ok(Some(Step::Prepare))
                    })();
                    match checked {
                        Ok(next) => next,
                        Err(check) => {
                            let sample = GitReadFailureSample::capture(OuterStep::GitUpstream(step), status.operation.as_ref(), check, None);
                            self.fail_git_read_wait(&mut r, "git-upstream-original-contract", sample);
                            return Err(invalid());
                        }
                    }
                }
                Step::Prepare => {
                    let action = {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_upstream.as_ref().ok_or_else(invalid)?;
                        if v.prepare_count >= 2
                            || v.read_count != v.prepare_count + 1
                            || v.applied != (v.prepare_count == 1)
                        {
                            return Err(invalid());
                        }
                        upstream::Action {
                            kind: upstream::Kind::SetUpstream,
                            expected_revision: v.revision.clone().ok_or_else(invalid)?,
                            expected_reference_revision: v
                                .reference_revision
                                .clone()
                                .ok_or_else(invalid)?,
                            branch: "refs/heads/main".into(),
                            head: r
                                .fixture
                                .git_upstream
                                .as_ref()
                                .ok_or_else(invalid)?
                                .target()
                                .into(),
                            remote: "origin".into(),
                            repository: REPOSITORY.into(),
                            identity: None,
                        }
                    };
                    let expected = local::Action::Upstream(action.clone()).public();
                    let started = document.git_local_prepare(local::Prepare {
                        project_id: project.clone(),
                        expected_document_revision: document.git_local_status().document_revision,
                        action: local::Action::Upstream(action.clone()),
                    })?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    let op = started.status.operation.ok_or_else(invalid)?;
                    if op.context.project_id != project
                        || op.phase != local::Phase::Prepare
                        || op.action != expected
                    {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                    if v.locals.len() != if v.prepare_count == 0 { 0 } else { 2 }
                        || v.locals.iter().any(|old| old.id == op.operation_id)
                    {
                        return Err(invalid());
                    }
                    v.locals.push(LocalOriginal::capture(&op));
                    v.action = Some(action);
                    Some(Step::PrepareWait)
                }
                Step::PrepareWait => {
                    let s = document.git_local_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    let f = r.fixture.git_upstream.as_ref().ok_or_else(invalid)?;
                    let original_hash = f.original_config_hash().to_owned();
                    let candidate_hash = f.candidate_config_hash().ok_or_else(invalid)?;
                    let index_hash = f.index_hash().to_owned();
                    let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                    if !same(v.locals.last(), &p) {
                        return Err(invalid());
                    }
                    if matches!(p.stage, read::Phase::Starting | read::Phase::Running) {
                        None
                    } else {
                        if !settled(&p) {
                            return Err(invalid());
                        }
                        let ready = s.review.ok_or_else(invalid)?;
                        let local::Review::Upstream(review) = &ready.review else {
                            return Err(invalid());
                        };
                        let after = v.prepare_count == 1;
                        let hash = if after { candidate_hash } else { original_hash };
                        let missing: Vec<String> = if after {
                            Vec::new()
                        } else {
                            fixture::CREATED.iter().map(|s| (*s).into()).collect()
                        };
                        if ready.context != p.context
                            || ready.action != p.action
                            || !review.matches(v.action.as_ref().ok_or_else(invalid)?)
                            || review.expected_index != index_hash
                            || review.original_config != hash
                            || review.unchanged != after
                            || review.additions
                                != if after {
                                    Vec::new()
                                } else {
                                    fixture::additions()
                                }
                            || review.missing_directories != missing
                        {
                            return Err(invalid());
                        }
                        // Status is reconciled from the SAME positively retired ticket;
                        // the child frame or a notification alone cannot create ReadyReview.
                        v.prepared = Some(ready);
                        v.prepare_count += 1;
                        Some(if after {
                            Step::CloseReview
                        } else {
                            Step::Apply
                        })
                    }
                }
                Step::Apply => {
                    let (id, expected, context) = {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_upstream.as_ref().ok_or_else(invalid)?;
                        let p = v.prepared.as_ref().ok_or_else(invalid)?;
                        if v.prepare_count != 1
                            || v.applied
                            || !matches!(&p.review,local::Review::Upstream(u) if !u.unchanged)
                        {
                            return Err(invalid());
                        }
                        (p.review_id.clone(), p.action.clone(), p.context.clone())
                    };
                    let started = document.git_local_apply(
                        local::Apply {
                            project_id: project,
                            expected_document_revision: document
                                .git_local_status()
                                .document_revision,
                            review_id: id,
                        },
                        control.application(),
                    )?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    let op = started.status.operation.ok_or_else(invalid)?;
                    if op.phase != local::Phase::Apply
                        || op.action != expected
                        || op.context != context
                    {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                    if v.locals.len() != 1 || v.locals.iter().any(|old| old.id == op.operation_id) {
                        return Err(invalid());
                    }
                    v.locals.push(LocalOriginal::capture(&op));
                    v.prepared = None;
                    Some(Step::ApplyWait)
                }
                Step::ApplyWait => {
                    let s = document.git_local_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    {
                        let r = self.record().ok_or_else(invalid)?;
                        if !same(
                            r.git_upstream.as_ref().ok_or_else(invalid)?.locals.last(),
                            &p,
                        ) {
                            return Err(invalid());
                        }
                    }
                    if matches!(p.stage, read::Phase::Starting | read::Phase::Running) {
                        None
                    } else {
                        if !settled(&p)
                            || s.review.is_some()
                            || p.result["state"] != "succeeded"
                            || p.result["settlement"] != "settled"
                            || !p.result["reason"].is_null()
                            || p.result["effectPhase"] != "config-returned"
                            || p.result["retainedPaths"] != json!([])
                            || !p.result["intent"].is_object()
                        {
                            return Err(invalid());
                        }
                        let (f, root, uid) = {
                            let r = self.record().ok_or_else(invalid)?;
                            (
                                r.fixture.git_upstream.clone().ok_or_else(invalid)?,
                                r.fixture.root.clone(),
                                r.fixture.uid,
                            )
                        };
                        let after = f.after(&root, uid).map_err(|_| invalid())?;
                        let mut r = self.record().ok_or_else(invalid)?;
                        let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                        v.applied = true;
                        v.after = Some(after);
                        Some(Step::Read)
                    }
                }
                Step::CloseReview => {
                    let (id, old) = {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_upstream.as_ref().ok_or_else(invalid)?;
                        let p = v.prepared.as_ref().ok_or_else(invalid)?;
                        if v.prepare_count != 2
                            || !v.applied
                            || v.closed
                            || !matches!(&p.review,local::Review::Upstream(u) if u.unchanged)
                        {
                            return Err(invalid());
                        }
                        (
                            p.review_id.clone(),
                            v.locals.last().cloned().ok_or_else(invalid)?,
                        )
                    };
                    let s = document.git_local_discard(&id)?;
                    let p = s.operation.ok_or_else(invalid)?;
                    if s.review.is_some() || !same(Some(&old), &p) || !settled(&p) {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_upstream.as_mut().ok_or_else(invalid)?;
                    v.closed = true;
                    v.prepared = None;
                    Some(Step::Finish)
                }
                Step::Finish => {
                    let (f, root, uid, after) = {
                        let r = self.record().ok_or_else(invalid)?;
                        (
                            r.fixture.git_upstream.clone().ok_or_else(invalid)?,
                            r.fixture.root.clone(),
                            r.fixture.uid,
                            r.git_upstream
                                .as_ref()
                                .ok_or_else(invalid)?
                                .after
                                .clone()
                                .ok_or_else(invalid)?,
                        )
                    };
                    f.verify_unchanged(&root, uid, &after)
                        .map_err(|_| invalid())?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    if r.step != OuterStep::GitUpstream(step)
                        || r.pending.is_some()
                        || !control.finish(r.git_upstream.as_ref().ok_or_else(invalid)?)
                    {
                        return Err(invalid());
                    }
                    r.file_readback = true;
                    r.step = OuterStep::Close;
                    None
                }
            })
        })();
        match outcome {
            Ok(Some(next)) if self.timely() => {
                let Some(mut r) = self.record() else { return };
                if r.step != OuterStep::GitUpstream(step) || r.pending.is_some() {
                    self.fail_with("git-upstream-original-contract");
                    return;
                }
                r.step = OuterStep::GitUpstream(next);
            }
            Ok(None) => {}
            _ => self.fail_with("git-upstream-original-contract"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_without_tracking_is_not_remote_or_commit_publication() {
        let first = std::sync::atomic::AtomicU8::new(0);
        let failed = AtomicBool::new(false);
        super::super::latch_failure(&first, &failed, "git-upstream-original-contract");
        super::super::latch_failure(&first, &failed, "observer-invariant");
        assert_eq!(
            super::super::first_failure_reason(&first),
            Some("git-upstream-original-contract")
        );
        let absent = json!({"state":"not-configured","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null});
        let gone = json!({"state":"gone","remote":"origin","mergeRef":"refs/heads/main","localRef":"refs/remotes/origin/main","head":null,"ahead":null,"behind":null});
        assert!(tracking(&absent, false));
        assert!(tracking(&gone, true));
        assert!(!tracking(&gone, false));
        assert!(!tracking(&absent, true));
        let mut claimed = gone;
        claimed["head"] = json!("a".repeat(40));
        assert!(!tracking(&claimed, true));
        let config = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n\tignorecase = true\n\tprecomposeunicode = false\n[user]\nname = MRK Upstream Fixture\nemail = upstream-fixture@example.invalid\n";
        assert!(fixture::fixture_config(config));
        for bad in [
            [config.as_slice(), b"[user]\n"].concat(),
            [config.as_slice(), b"[include]\npath = other\n"].concat(),
            [config.as_slice(), b"\n"].concat(),
            String::from_utf8_lossy(config)
                .replace("ignorecase = true", "ignorecase = true\nignorecase = true")
                .into_bytes(),
            String::from_utf8_lossy(config)
                .replace("MRK Upstream Fixture", "other user")
                .into_bytes(),
        ] {
            assert!(!fixture::fixture_config(&bad));
        }
    }
}
