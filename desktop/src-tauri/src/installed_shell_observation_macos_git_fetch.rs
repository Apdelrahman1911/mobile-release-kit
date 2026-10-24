//! Four fixed, nonshipping Fetch journeys on the existing installed observer.
//! Only provider BYTES are synthetic. This control cannot construct a SourceBook,
//! Connected session, GO, native receipt, replacement clock or final-CAS witness.
use super::{Case as OuterCase, DocumentBinding, GitReadCheck as ReadCheck, GitReadFailureSample, Observation, Step as OuterStep};
use crate::{
    error::BridgeError, git_fetch_protocol as fetch, git_local_protocol as local,
    git_read_protocol as read, github_connection_protocol as github,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};

#[path = "installed_shell_observation_macos_git_fetch_fixture.rs"]
mod fixture;
pub(super) use fixture::Fixture;
pub(crate) const CONNECTION_ENTRY: &str = "github_fetch_connection_observation_bootstrap.py";
pub(crate) const REMOTE_ENTRY: &str = "git_fetch_observation_bootstrap.py";
pub(crate) const DATA_FILE: &str = "mrk-fetch-observation.json";
pub(crate) const DATA_LIMIT: u64 = 64 * 1024;
pub(crate) const MARKER: &[u8] = b"MRK_FETCH_OBSERVER=returned-with-original-open\n";
pub(crate) const ACCOUNT: &str = "mrk-fetch-fixture";
pub(crate) const NAMES: [&str; 4] = [
    "git-fetch-pack",
    "git-fetch-corrupt",
    "git-fetch-limit",
    "git-fetch-held-helper",
];
pub(crate) const SECONDS: u64 = 120;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    Pack,
    Corrupt,
    Limit,
    Held,
}
impl Case {
    pub(crate) const ALL: [Self; 4] = [Self::Pack, Self::Corrupt, Self::Limit, Self::Held];
    pub(crate) fn name(self) -> &'static str {
        NAMES[self as usize]
    }
    pub(super) fn parse(v: &std::ffi::OsStr) -> Option<Self> {
        Self::ALL.into_iter().find(|c| v == c.name())
    }
    pub(crate) fn coordinate(self) -> String {
        format!("{ACCOUNT}/{}", self.name())
    }
    fn token(self) -> String {
        format!("MRK-NON-CREDENTIAL-FETCH-OBSERVER-{}", self.name())
    }
}
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
    (fetch::oid(t.0) && decimal(t.1) && decimal(t.2)).then_some(t)
}
fn support(home: &Path) -> Option<PathBuf> {
    (home != Path::new("/") && crate::asset_session::installed_macos_selection_path_bounded(home))
        .then(|| home.join("Library/Application Support"))
}
pub(super) fn fixture_root(home: &Path) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    Some(support(home)?.join(format!("mrk-macos-aqua-{s}-{r}-{a}-git-fetch-native")))
}
fn application_root(home: &Path, case: Case) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    Some(
        support(home)?
            .join(format!("mrk-macos-aqua-fetch-{s}-{r}-{a}"))
            .join(case.name())
            .join("dev.mobile-release-kit.desktop"),
    )
}

#[derive(Clone)]
struct Original {
    id: String,
    digest: String,
    result: Option<Sample>,
}
#[derive(Clone)]
struct Sample {
    ok: bool,
    status: Option<read::Outcome>,
    reason: Option<String>,
    publication: bool,
}
#[derive(Default)]
struct Trace {
    prepare: Option<Original>,
    apply: Option<Original>,
    marker: bool,
    producer_pending: bool,
    stop: bool,
}
pub(crate) struct Registration {
    control: Arc<Control>,
    document: Weak<()>,
}
pub(crate) struct Control {
    case: Case,
    project: PathBuf,
    application: PathBuf,
    original: OnceLock<Weak<Observation>>,
    document: OnceLock<Weak<()>>,
    claimed: AtomicBool,
    returned: AtomicBool,
    complete: AtomicBool,
    tool: OnceLock<read::Snapshot>,
    data: OnceLock<read::Snapshot>,
    trace: Mutex<Trace>,
}
impl Control {
    pub(super) fn new(case: Case, project: &Path, uid: u32) -> Result<Arc<Self>, ()> {
        if !cfg!(target_arch = "aarch64") || uid == 0 {
            return Err(());
        }
        let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map_err(|_| ())?
            .ok_or(())?;
        if u.uid.as_raw() != uid || project != fixture_root(&u.dir).ok_or(())?.join(case.name()) {
            return Err(());
        }
        Ok(Arc::new(Self {
            case,
            project: project.to_owned(),
            application: application_root(&u.dir, case).ok_or(())?,
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            tool: OnceLock::new(),
            data: OnceLock::new(),
            trace: Mutex::new(Trace::default()),
        }))
    }
    fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| {
            q.case == OuterCase::GitFetch(self.case)
                && q.git_fetch
                    .as_ref()
                    .is_some_and(|c| std::ptr::eq(c.as_ref(), self))
        })
    }
    pub(crate) fn registered(&self, document: &Arc<()>) -> bool {
        self.claimed.load(Ordering::SeqCst)
            && self
                .document
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|d| Arc::ptr_eq(&d, document))
            && self.observation().is_some()
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
    pub(crate) fn live(&self) -> bool {
        self.document
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|d| self.bound(&d))
            && !self.complete.load(Ordering::SeqCst)
            && self.observation().is_some_and(|q| q.timely())
    }
    pub(crate) fn project(&self) -> &Path {
        &self.project
    }
    pub(crate) fn application(&self) -> &Path {
        &self.application
    }
    pub(crate) fn held_case(&self) -> bool {
        self.case == Case::Held
    }
    pub(crate) fn completed(&self) -> bool {
        self.complete.load(Ordering::SeqCst)
    }
    pub(crate) fn fail(&self) {
        if let Some(q) = self.observation() {
            q.fail_with("git-fetch-original-contract");
        }
    }
    pub(crate) fn pin_sources(
        &self,
        tool: &read::Snapshot,
        data: &read::Snapshot,
        root: &str,
    ) -> bool {
        if !self.live()
            || Path::new(root) != self.project
            || tool.identity.3 != 0
            || data.identity.3 == 0
            || data.identity.6 == 0
            || data.identity.6 > DATA_LIMIT
        {
            return false;
        }
        // Actual SourceBook snapshots, not supplied manifest or version text.
        let matched = |slot: &OnceLock<read::Snapshot>, v: &read::Snapshot| {
            if let Some(old) = slot.get() {
                old == v
            } else {
                slot.set(v.clone()).is_ok()
            }
        };
        matched(&self.tool, tool) && matched(&self.data, data)
    }
    pub(crate) fn observed(&self, request: &local::Request) -> bool {
        if !self.live()
            || request.action.kind() != local::Kind::Fetch
            || request.native.as_ref().is_none_or(|n| {
                Path::new(&n.root) != self.project || self.tool.get() != Some(&n.tool)
            })
        {
            return false;
        }
        let Ok(mut t) = self.trace.try_lock() else {
            return false;
        };
        let previous = t.prepare.as_ref().is_some_and(|p| {
            p.result
                .as_ref()
                .is_some_and(|v| v.ok && v.status == Some(read::Outcome::Ok))
        });
        let slot = if request.phase == local::Phase::Prepare {
            &mut t.prepare
        } else {
            if !previous {
                return false;
            }
            &mut t.apply
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(Original {
            id: request.id.clone(),
            digest: request.digest.clone(),
            result: None,
        });
        true
    }
    pub(crate) fn marker(&self, id: &str) -> bool {
        let Ok(mut t) = self.trace.try_lock() else {
            return false;
        };
        if !self.live()
            || self.case != Case::Held
            || t.marker
            || t.stop
            || t.apply
                .as_ref()
                .is_none_or(|p| p.id != id || p.result.is_some())
        {
            return false;
        }
        t.marker = true;
        true
    }
    pub(crate) fn marker_pending(&self, id: &str) -> bool {
        self.trace.try_lock().is_ok_and(|t| {
            t.marker
                && !t.producer_pending
                && !t.stop
                && t.apply
                    .as_ref()
                    .is_some_and(|p| p.id == id && p.result.is_none())
        })
    }
    pub(crate) fn producer_pending(&self, id: &str) -> bool {
        let Ok(mut t) = self.trace.try_lock() else {
            return false;
        };
        if !self.live()
            || self.case != Case::Held
            || !t.marker
            || t.stop
            || t.apply
                .as_ref()
                .is_none_or(|p| p.id != id || p.result.is_some())
        {
            return false;
        }
        t.producer_pending = true;
        true
    }
    pub(crate) fn window(&self, id: &str) -> bool {
        self.trace.try_lock().is_ok_and(|t| {
            self.live()
                && t.marker
                && t.producer_pending
                && !t.stop
                && t.apply
                    .as_ref()
                    .is_some_and(|p| p.id == id && p.result.is_none())
        })
    }
    pub(crate) fn stop_entered(&self, id: &str) -> bool {
        let Ok(mut t) = self.trace.try_lock() else {
            return false;
        };
        if !self.live()
            || !t.marker
            || !t.producer_pending
            || t.stop
            || t.apply
                .as_ref()
                .is_none_or(|p| p.id != id || p.result.is_some())
        {
            return false;
        }
        t.stop = true;
        true
    }
    pub(crate) fn stderr_allowed(&self, id: &str, bytes: &[u8]) -> bool {
        self.trace.try_lock().is_ok_and(|t| {
            let held_apply = self.held_case() && t.apply.as_ref().is_some_and(|p| p.id == id);
            if held_apply {
                bytes == MARKER && t.marker && t.producer_pending && t.stop
            } else {
                bytes.is_empty()
            }
        })
    }
    pub(crate) fn retired(
        &self,
        request: &local::Request,
        receipt: &crate::supervisor::GitLocalReceipt,
    ) {
        let result = (|| {
            let mut t = self.trace.try_lock().ok()?;
            let slot = if request.phase == local::Phase::Prepare {
                &mut t.prepare
            } else {
                &mut t.apply
            };
            let p = slot.as_mut().filter(|p| {
                p.id == request.id && p.digest == request.digest && p.result.is_none()
            })?;
            let sample = match receipt {
                crate::supervisor::GitLocalReceipt::Settled {
                    outcome: Ok(v),
                    was_unknown: false,
                } => Sample {
                    ok: true,
                    status: Some(v.status),
                    reason: v.reason.clone(),
                    publication: v.publication == local::Publication::FetchReturned,
                },
                crate::supervisor::GitLocalReceipt::Settled {
                    outcome: Err(e),
                    was_unknown: false,
                } if self.held_case()
                    && matches!(e.code.as_str(), "cancelled" | "shutting_down") =>
                {
                    Sample {
                        ok: true,
                        status: Some(read::Outcome::Cancelled),
                        reason: Some("authorization".into()),
                        publication: false,
                    }
                }
                crate::supervisor::GitLocalReceipt::Settled {
                    outcome: Err(e),
                    was_unknown: false,
                } => Sample {
                    ok: false,
                    status: None,
                    reason: Some(e.code.to_owned()),
                    publication: false,
                },
                _ => return None,
            };
            p.result = Some(sample);
            Some(())
        })();
        if result.is_none() {
            self.fail()
        }
    }
    fn checked_sample(&self, phase: local::Phase, p: &local::Projection) -> bool {
        self.trace.try_lock().is_ok_and(|t| {
            let original = if phase == local::Phase::Prepare {
                &t.prepare
            } else {
                &t.apply
            };
            original.as_ref().is_some_and(|v| {
                v.id == p.operation_id
                    && v.result.as_ref().is_some_and(|s| {
                        s.ok && s.status == p.outcome
                            && s.reason == p.reason
                            && s.publication
                                == (phase == local::Phase::Apply && self.case == Case::Pack)
                    })
            })
        })
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>()
            // Observer-only sole-reader wrapper, selected profile Arc cells,
            // notification future and fixed scalar scratch. Old buffers and
            // native/driver slots keep their full existing reservations.
            .checked_add(1024)?
            // Extra nonshipping helper DATA: one 1MiB C probe buffer, bounded
            // transcript/base64 copies and <=128 fixture calls/four FD leases.
            // Charged simultaneously, never credited against normal Fetch.
            .checked_add(2 * 1024 * 1024)?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.project.capacity())?
            .checked_add(self.application.capacity())?;
        for p in [self.tool.get(), self.data.get()].into_iter().flatten() {
            n = n.checked_add(p.sha256.capacity())?;
        }
        let t = self.trace.try_lock().ok()?;
        for p in [&t.prepare, &t.apply].into_iter().flatten() {
            n = n
                .checked_add(p.id.capacity())?
                .checked_add(p.digest.capacity())?;
            if let Some(s) = &p.result {
                if let Some(r) = &s.reason {
                    n = n.checked_add(r.capacity())?;
                }
            }
        }
        drop(t);
        let q = self.observation()?;
        let r = q.record.try_lock().ok()?;
        n = n
            .checked_add(r.git_fetch.as_ref()?.retained_bytes()?)?
            .checked_add(
                r.fixture
                    .git_fetch
                    .as_ref()?
                    .retained_bytes()?
                    .checked_mul(2)?,
            )?;
        Some(n)
    }
    fn finish(&self) -> bool {
        let Ok(t) = self.trace.try_lock() else {
            return false;
        };
        if !self.live()
            || self.tool.get().is_none()
            || self.data.get().is_none()
            || t.prepare
                .as_ref()
                .and_then(|p| p.result.as_ref())
                .is_none_or(|s| !s.ok || s.status != Some(read::Outcome::Ok) || s.publication)
            || t.apply
                .as_ref()
                .and_then(|p| p.result.as_ref())
                .is_none_or(|s| !s.ok)
            || (self.case == Case::Held) != (t.marker && t.producer_pending && t.stop)
        {
            return false;
        }
        !self.complete.swap(true, Ordering::SeqCst)
    }
    fn attach(
        self: &Arc<Self>,
        q: &Arc<Observation>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if q.case != OuterCase::GitFetch(self.case)
            || std::thread::current().id() != q.main
            || !q.timely()
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
        document.register_installed_macos_git_fetch(Registration {
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
    pub(crate) fn git_fetch_application(&self) -> Option<&Path> {
        self.git_fetch.as_ref().map(|c| c.application())
    }
    pub(crate) fn attach_git_fetch(
        self: &Arc<Self>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if let Some(c) = &self.git_fetch {
            c.attach(self, document)?
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Connect,
    Connected,
    Read,
    ReadWait,
    Prepare,
    PrepareWait,
    Apply,
    ApplyWait,
    Disconnect,
    Disconnected,
    Finish,
}
#[derive(Default)]
pub(super) struct Record {
    session: Option<String>,
    connection_operation: Option<String>,
    connection_revision: u32,
    read_operation: Option<String>,
    revision: Option<String>,
    reference_revision: Option<String>,
    active: Option<local::Projection>,
    prepared: Option<local::Prepared>,
    result: Value,
    connected: bool,
    read: bool,
    applied: bool,
    disconnected: bool,
    normal_quit: bool,
}
impl Record {
    fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>();
        for s in [
            &self.session,
            &self.connection_operation,
            &self.read_operation,
            &self.revision,
            &self.reference_revision,
        ]
        .into_iter()
        .flatten()
        {
            n = n.checked_add(s.capacity())?;
        }
        // Bounded largest original projection/review plus serialization scratch;
        // NOT credit from discarding the same preparer or native originals.
        n.checked_add(2 * local::REVIEW_BACKING)
    }
    pub(super) fn final_originals(&mut self, c: &Control, id: u32, finality: bool) -> bool {
        if self.normal_quit
            || !c.completed()
            || !finality
            || id != 2
            || !self.connected
            || !self.read
            || !self.applied
            || !self.disconnected
        {
            return false;
        }
        self.normal_quit = true;
        true
    }
    pub(super) fn report(&self, c: &Control) -> Option<Value> {
        if !self.normal_quit || !c.completed() || !self.disconnected {
            return None;
        }
        let t = c.trace.try_lock().ok()?;
        let tool = c.tool.get()?;
        let p = t.apply.as_ref()?.result.as_ref()?;
        Some(
            json!({"mechanism":"same-original-git-fetch-v1","case":c.case.name(),
            "syntheticProviderBytes":true,"connectionOriginalJoined":self.connected,"readOriginalJoined":self.read,
            "prepareOriginalJoined":true,"applyOriginalJoined":self.applied,"connectionRetired":self.disconnected,
            "publication":p.publication,"helperReturnedBeforeAllCopyEof":t.marker,"producerPendingBeforeStop":t.producer_pending,
            "sameTicketStop":t.stop,"toolSha256":tool.sha256,"normalQuitOriginal":2,
            "allOriginalsSettled":true,"worktreePreserved":true,"shippingNominationEnabled":false,
            "tlsQualified":false,"liveAccountQualified":false,"productionQualified":false}),
        )
    }
}
impl Observation {
    pub(super) fn git_fetch_final_fixture_readback(&self) -> Option<()> {
        let c = self.git_fetch.as_ref()?;
        if self.case != OuterCase::GitFetch(c.case) || !c.completed() { return None; }
        let (fixture, root, uid, result) = {
            let r = self.record()?;
            let v = r.git_fetch.as_ref()?;
            if !self.final_fixture_shape(&r) || !v.normal_quit { return None; }
            (r.fixture.git_fetch.as_ref()?.clone(), r.fixture.root.clone(), r.fixture.uid, v.result.clone())
        };
        if !self.timely() || fixture.verify(&root, uid, c.case, &result).is_err() { return None; }
        let r = self.record()?;
        (self.final_fixture_shape(&r) && c.completed()
            && r.fixture.root == root && r.fixture.uid == uid
            && r.fixture.git_fetch.as_ref() == Some(&fixture)
            && r.git_fetch.as_ref().is_some_and(|v| v.normal_quit && v.result == result)).then_some(())
    }
    pub(super) async fn git_fetch_tick(
        self: &Arc<Self>,
        _app: &tauri::AppHandle,
        document: &DocumentBinding,
        step: Step,
    ) {
        let Some(control) = &self.git_fetch else {
            self.fail_with("git-fetch-original-contract");
            return;
        };
        let invalid = BridgeError::invalid;
        let outcome: Result<Option<Step>, BridgeError> = (|| {
            let project = self
                .record()
                .and_then(|r| r.project.as_ref().map(|p| p.id.clone()))
                .ok_or_else(invalid)?;
            Ok(match step {
                Step::Connect => {
                    let s=document.github_connection_connect_token(&json!({"projectId":project,"repository":control.case.coordinate(),"token":control.case.token()}))?;
                    let session = s
                        .session
                        .as_ref()
                        .filter(|v| {
                            v.state == github::SessionState::Checking
                                && v.project_id == project
                                && v.target_repository == control.case.coordinate()
                        })
                        .ok_or_else(invalid)?;
                    let op = s
                        .operation
                        .as_ref()
                        .filter(|v| {
                            v.kind == github::OperationKind::Connect
                                && v.phase == github::Phase::Running
                        })
                        .ok_or_else(invalid)?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_fetch.as_mut().ok_or_else(invalid)?;
                    v.session = Some(session.id.clone());
                    v.connection_operation = Some(op.id.clone());
                    Some(Step::Connected)
                }
                Step::Connected => {
                    let s = document.github_connection_status();
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_fetch.as_mut().ok_or_else(invalid)?;
                    let session = s
                        .session
                        .as_ref()
                        .filter(|p| {
                            Some(&p.id) == v.session.as_ref()
                                && p.project_id == project
                                && p.target_repository == control.case.coordinate()
                        })
                        .ok_or_else(invalid)?;
                    let op = s
                        .operation
                        .as_ref()
                        .filter(|p| {
                            Some(&p.id) == v.connection_operation.as_ref()
                                && p.kind == github::OperationKind::Connect
                        })
                        .ok_or_else(invalid)?;
                    if op.phase == github::Phase::Running {
                        None
                    } else {
                        if op.phase != github::Phase::Settled
                            || op.reason != github::Reason::None
                            || session.state != github::SessionState::Connected
                            || s.account.state != github::FactState::Observed
                            || s.repository.state != github::FactState::Observed
                            || s.account
                                .value
                                .as_ref()
                                .is_none_or(|a| a.id != "811" || a.login != ACCOUNT)
                            || s.repository.value.as_ref().is_none_or(|a| {
                                a.id != "822" || a.full_name != control.case.coordinate()
                            })
                        {
                            return Err(invalid());
                        }
                        v.connection_revision = s.revision;
                        v.connected = true;
                        Some(Step::Read)
                    }
                }
                Step::Read => {
                    let s = document.git_read_status();
                    let started = document.git_read_start(read::Start {
                        project_id: project,
                        expected_document_revision: s.document_revision,
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
                    let op = started.status.operation.as_ref().ok_or_else(invalid)?;
                    self.record()
                        .ok_or_else(invalid)?
                        .git_fetch
                        .as_mut()
                        .ok_or_else(invalid)?
                        .read_operation = Some(op.operation_id.clone());
                    Some(Step::ReadWait)
                }
                Step::ReadWait => {
                    let status = document.git_read_status();
                    if status.operation.is_none() {
                        self.fail_git_read_missing(OuterStep::GitFetch(step), "git-fetch-original-contract");
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    let checked = (|| {
                        let p = status.operation.as_ref().ok_or(ReadCheck::MissingOperation)?;
                        let v = r.git_fetch.as_mut().ok_or(ReadCheck::MissingOriginal)?;
                        let original = v.read_operation.as_deref().ok_or(ReadCheck::MissingOriginal)?;
                        if original != p.operation_id { return Err(ReadCheck::OriginalMismatch); }
                        if !super::git_read_wait_terminal(p)? { return Ok(None); }
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
                        v.read = true;
                        Ok(Some(Step::Prepare))
                    })();
                    match checked {
                        Ok(next) => next,
                        Err(check) => {
                            let sample = GitReadFailureSample::capture(OuterStep::GitFetch(step), status.operation.as_ref(), check, None);
                            self.fail_git_read_wait(&mut r, "git-fetch-original-contract", sample);
                            return Err(invalid());
                        }
                    }
                }
                Step::Prepare => {
                    let a = {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_fetch.as_ref().ok_or_else(invalid)?;
                        fetch::Action {
                            kind: fetch::Kind::Fetch,
                            expected_revision: v.revision.clone().ok_or_else(invalid)?,
                            expected_reference_revision: v
                                .reference_revision
                                .clone()
                                .ok_or_else(invalid)?,
                            remote: "origin".into(),
                            reference: "refs/heads/main".into(),
                            connection_session_id: v.session.clone().ok_or_else(invalid)?,
                            expected_connection_revision: v.connection_revision,
                        }
                    };
                    let started = document.git_local_prepare(local::Prepare {
                        project_id: project,
                        expected_document_revision: document.git_local_status().document_revision,
                        action: local::Action::Fetch(a),
                    })?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    self.record()
                        .ok_or_else(invalid)?
                        .git_fetch
                        .as_mut()
                        .ok_or_else(invalid)?
                        .active = Some(started.status.operation.ok_or_else(invalid)?);
                    Some(Step::PrepareWait)
                }
                Step::PrepareWait => {
                    let s = document.git_local_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_fetch.as_mut().ok_or_else(invalid)?;
                    if !same(v.active.as_ref(), &p) {
                        return Err(invalid());
                    }
                    if matches!(p.stage, read::Phase::Starting | read::Phase::Running) {
                        None
                    } else {
                        if p.stage != read::Phase::Settled
                            || p.outcome != Some(read::Outcome::Ok)
                            || p.reason.is_some()
                            || !control.checked_sample(local::Phase::Prepare, &p)
                        {
                            return Err(invalid());
                        }
                        let ready = s.review.ok_or_else(invalid)?;
                        let local::Review::Fetch(review) = &ready.review else {
                            return Err(invalid());
                        };
                        if review.up_to_date()
                            || review.repository != control.case.coordinate()
                            || review.account_id != "811"
                            || review.repository_id != "822"
                            || review.login != ACCOUNT
                        {
                            return Err(invalid());
                        }
                        let f = r.fixture.git_fetch.as_ref().ok_or_else(invalid)?;
                        if review.head.as_deref() != Some(f.base())
                            || review.expected_target.as_deref() != Some(f.base())
                            || review.candidate_ref_oid != f.target()
                        {
                            return Err(invalid());
                        }
                        r.git_fetch.as_mut().ok_or_else(invalid)?.prepared = Some(ready);
                        Some(Step::Apply)
                    }
                }
                Step::Apply => {
                    let review = self
                        .record()
                        .and_then(|r| {
                            r.git_fetch
                                .as_ref()?
                                .prepared
                                .as_ref()
                                .map(|p| p.review_id.clone())
                        })
                        .ok_or_else(invalid)?;
                    let started = document.git_local_apply(
                        local::Apply {
                            project_id: project,
                            expected_document_revision: document
                                .git_local_status()
                                .document_revision,
                            review_id: review,
                        },
                        control.application(),
                    )?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    self.record()
                        .ok_or_else(invalid)?
                        .git_fetch
                        .as_mut()
                        .ok_or_else(invalid)?
                        .active = Some(started.status.operation.ok_or_else(invalid)?);
                    Some(Step::ApplyWait)
                }
                Step::ApplyWait => {
                    let s = document.git_local_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    let old = self
                        .record()
                        .and_then(|r| r.git_fetch.as_ref()?.active.clone());
                    if !same(old.as_ref(), &p) {
                        return Err(invalid());
                    }
                    if matches!(
                        p.stage,
                        read::Phase::Starting | read::Phase::Running | read::Phase::Stopping
                    ) {
                        if control.held_case() && control.window(&p.operation_id) {
                            if !document.installed_git_fetch_pending(control, &p.operation_id)
                                || !control.stop_entered(&p.operation_id)
                            {
                                return Err(invalid());
                            }
                            document.git_local_cancel(&p.operation_id)?;
                        }
                        None
                    } else {
                        if p.stage != read::Phase::Settled
                            || !control.checked_sample(local::Phase::Apply, &p)
                        {
                            return Err(invalid());
                        }
                        match control.case {
                            Case::Pack => {
                                if p.outcome != Some(read::Outcome::Ok)
                                    || p.result["state"] != "succeeded"
                                    || p.result["effectPhase"] != "ref-published"
                                {
                                    return Err(invalid());
                                }
                            }
                            Case::Limit => {
                                if p.outcome != Some(read::Outcome::Ok)
                                    || p.result["state"] != "recovery-required"
                                    || p.result["reason"] != "response-limit"
                                    || p.result["intent"] != Value::Null
                                {
                                    return Err(invalid());
                                }
                            }
                            Case::Corrupt => {
                                if p.outcome != Some(read::Outcome::Ok)
                                    || p.result["state"] != "recovery-required"
                                    || p.result["intent"] != Value::Null
                                    || p.result["reason"] != "command-failed"
                                {
                                    return Err(invalid());
                                }
                            }
                            Case::Held => {
                                let cancelled = p.outcome == Some(read::Outcome::Cancelled)
                                    && p.result.is_null();
                                // The real core may return its known private staging
                                // recovery before the outer engine reports STOP.
                                let retained = p.outcome == Some(read::Outcome::Ok)
                                    && p.result["state"] == "recovery-required"
                                    && p.result["intent"].is_null()
                                    && p.result["effectPhase"] == "not-published"
                                    && matches!(
                                        p.result["reason"].as_str(),
                                        Some("command-failed" | "authorization")
                                    );
                                if !cancelled && !retained {
                                    return Err(invalid());
                                }
                            }
                        }
                        let mut r = self.record().ok_or_else(invalid)?;
                        let v = r.git_fetch.as_mut().ok_or_else(invalid)?;
                        v.applied = true;
                        v.result = p.result;
                        Some(Step::Disconnect)
                    }
                }
                Step::Disconnect => {
                    let session = self
                        .record()
                        .and_then(|r| r.git_fetch.as_ref()?.session.clone())
                        .ok_or_else(invalid)?;
                    document.github_connection_disconnect(&json!({"sessionId":session}))?;
                    Some(Step::Disconnected)
                }
                Step::Disconnected => {
                    let s = document.github_connection_status();
                    if s.session.is_some() {
                        if s.session
                            .as_ref()
                            .is_some_and(|v| v.state == github::SessionState::Disconnecting)
                        {
                            None
                        } else {
                            return Err(invalid());
                        }
                    } else {
                        if s.operation
                            .as_ref()
                            .is_some_and(|v| v.phase != github::Phase::Settled)
                        {
                            return Err(invalid());
                        }
                        self.record()
                            .ok_or_else(invalid)?
                            .git_fetch
                            .as_mut()
                            .ok_or_else(invalid)?
                            .disconnected = true;
                        Some(Step::Finish)
                    }
                }
                Step::Finish => {
                    let (fixture, root, uid, result) = {
                        let r = self.record().ok_or_else(invalid)?;
                        (
                            r.fixture.git_fetch.clone().ok_or_else(invalid)?,
                            r.fixture.root.clone(),
                            r.fixture.uid,
                            r.git_fetch.as_ref().ok_or_else(invalid)?.result.clone(),
                        )
                    };
                    fixture
                        .verify(&root, uid, control.case, &result)
                        .map_err(|_| invalid())?;
                    if !control.finish() {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    if r.step != OuterStep::GitFetch(step) || r.pending.is_some() {
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
                if r.step != OuterStep::GitFetch(step) || r.pending.is_some() {
                    self.fail_with("git-fetch-original-contract");
                    return;
                }
                r.step = OuterStep::GitFetch(next);
            }
            Ok(None) => {}
            _ => self.fail_with("git-fetch-original-contract"),
        }
    }
}
fn same(old: Option<&local::Projection>, p: &local::Projection) -> bool {
    old.is_some_and(|o| {
        o.operation_id == p.operation_id
            && o.context == p.context
            && o.phase == p.phase
            && o.action == p.action
    })
}
