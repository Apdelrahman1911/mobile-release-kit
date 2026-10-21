//! Three fixed, nonshipping Push journeys on the existing installed observer.
//! Only provider BYTES are synthetic. This control cannot construct a SourceBook,
//! Connected session, GO, native receipt, replacement clock or final-CAS witness.
use super::{Case as OuterCase, DocumentBinding, Observation, Step as OuterStep};
use crate::{
    error::BridgeError, git_local_protocol as local, git_push_protocol as push,
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

#[path = "installed_shell_observation_macos_git_push_create.rs"]
mod create;
#[path = "installed_shell_observation_macos_git_push_fixture.rs"]
mod fixture;
pub(super) use fixture::Fixture;
pub(crate) const CONNECTION_ENTRY: &str = "github_push_connection_observation_bootstrap.py";
pub(crate) const REMOTE_ENTRY: &str = "git_push_observation_bootstrap.py";
pub(crate) const DATA_FILE: &str = "mrk-push-observation.json";
pub(crate) const DATA_LIMIT: u64 = 4096;
pub(crate) const MARKER: &[u8] = b"MRK_PUSH_OBSERVER=refused-with-original-open\n";
pub(crate) const ACCOUNT: &str = "mrk-push-fixture";
pub(crate) const NAMES: [&str; 3] = ["git-push-pack", "git-push-stale", "git-push-held-refusal"];
pub(crate) const SECONDS: u64 = 120;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    Pack,
    Stale,
    Held,
    Create(create::Case),
}
impl Case {
    pub(crate) const ALL: [Self; 8] = [Self::Pack, Self::Stale, Self::Held,
        Self::Create(create::Case::Empty), Self::Create(create::Case::Equal),
        Self::Create(create::Case::Stale), Self::Create(create::Case::Race), Self::Create(create::Case::Held)];
    pub(crate) fn name(self) -> &'static str {
        match self { Self::Pack=>NAMES[0], Self::Stale=>NAMES[1], Self::Held=>NAMES[2], Self::Create(c)=>c.name() }
    }
    fn create(self) -> Option<create::Case> { if let Self::Create(c)=self {Some(c)}else{None} }
    pub(crate) fn kind(self) -> local::Kind { if self.create().is_some(){local::Kind::PushNewBranch}else{local::Kind::Push} }
    fn apply_requested(self) -> bool {self.create().is_none_or(create::Case::apply_requested)}
    fn publication(self) -> bool {matches!(self,Self::Pack|Self::Create(create::Case::Empty))}
    pub(super) fn namespace(self) -> &'static [&'static str] {
        if self.create().is_some(){&[create::NAMES[0],create::NAMES[1],create::NAMES[2],create::NAMES[3],create::NAMES[4],"state"]}
        else{&[NAMES[0],NAMES[1],NAMES[2],"state"]}
    }
    pub(super) fn parse(v: &std::ffi::OsStr) -> Option<Self> {
        Self::ALL.into_iter().find(|c| v == c.name())
    }
    pub(crate) fn coordinate(self) -> String {
        format!("{ACCOUNT}/{}", self.name())
    }
    fn token(self) -> String {
        format!("MRK-NON-CREDENTIAL-PUSH-OBSERVER-{}", self.name())
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
    (crate::git_fetch_protocol::oid(t.0) && decimal(t.1) && decimal(t.2)).then_some(t)
}
fn support(home: &Path) -> Option<PathBuf> {
    (home != Path::new("/") && crate::asset_session::installed_macos_selection_path_bounded(home))
        .then(|| home.join("Library/Application Support"))
}
pub(super) fn fixture_root(home: &Path, case: Case) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    let scope=if case.create().is_some(){create::SCOPE}else{"git-push-native"};
    Some(support(home)?.join(format!("mrk-macos-aqua-{s}-{r}-{a}-{scope}")))
}
fn application_root(home: &Path, case: Case) -> Option<PathBuf> {
    let (s, r, a) = tuple()?;
    let tag=if case.create().is_some(){"push-create"}else{"push"};
    Some(
        support(home)?
            .join(format!("mrk-macos-aqua-{tag}-{s}-{r}-{a}"))
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
        if u.uid.as_raw() != uid || project != fixture_root(&u.dir,case).ok_or(())?.join(case.name()) {
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
            q.case == OuterCase::GitPush(self.case)
                && q.git_push
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
    pub(crate) fn kind(&self) -> local::Kind {self.case.kind()}
    pub(crate) fn held_case(&self) -> bool {
        matches!(self.case,Case::Held|Case::Create(create::Case::Held))
    }
    pub(crate) fn completed(&self) -> bool {
        self.complete.load(Ordering::SeqCst)
    }
    pub(crate) fn fail(&self) {
        if let Some(q) = self.observation() {
            q.fail_with("git-push-original-contract");
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
            || request.action.kind() != self.kind()
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
            || !self.held_case()
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
            || !self.held_case()
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
                    publication: v.publication == local::Publication::PushReturned,
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
                                == (phase == local::Phase::Apply && self.case.publication())
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
            // Fixed additional helper/fixture DATA, charged simultaneously:
            // <=4KiB transcript and 64-call/four-lease acquisition, fixed
            // provider responses, count/hash-only sender, and native <=64KiB
            // independent fixture reads. No PACK copy or Fetch probe buffer.
            // This must fit existing Push200 admission; it grants no quota.
            .checked_add(1024 * 1024)?
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
            .checked_add(r.git_push.as_ref()?.retained_bytes()?)?
            .checked_add(
                r.fixture
                    .git_push
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
            || t.prepare.as_ref().and_then(|p|p.result.as_ref()).is_none_or(|s|
                !s.ok || s.publication || if self.case.apply_requested(){s.status!=Some(read::Outcome::Ok)}
                    else{s.status!=Some(read::Outcome::Refused)||s.reason.as_deref()!=Some("target-changed")})
            || if self.case.apply_requested(){t.apply.as_ref().and_then(|p|p.result.as_ref()).is_none_or(|s|!s.ok)}
                else{t.apply.is_some()}
            || self.held_case() != (t.marker && t.producer_pending && t.stop)
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
        if q.case != OuterCase::GitPush(self.case)
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
        document.register_installed_macos_git_push(Registration {
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
    pub(crate) fn git_push_application(&self) -> Option<&Path> {
        self.git_push.as_ref().map(|c| c.application())
    }
    pub(crate) fn attach_git_push(
        self: &Arc<Self>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if let Some(c) = &self.git_push {
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
            || self.applied != c.case.apply_requested()
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
        let publication=if c.case.apply_requested(){t.apply.as_ref()?.result.as_ref()?.publication}else{
            if t.apply.is_some() || self.applied{return None} false};
        let mut value=json!({"mechanism":"same-original-git-push-v1","case":c.case.name(),
            "syntheticProviderBytes":true,"connectionOriginalJoined":self.connected,"readOriginalJoined":self.read,
            "prepareOriginalJoined":true,"applyOriginalJoined":self.applied,"connectionRetired":self.disconnected,
            "remoteReturned":publication,"helperRefusedBeforeAllCopyEof":t.marker,"producerPendingBeforeStop":t.producer_pending,
            "sameTicketStop":t.stop,"toolSha256":tool.sha256,"normalQuitOriginal":2,
            "allOriginalsSettled":true,"worktreePreserved":true,"shippingNominationEnabled":false,
            "tlsQualified":false,"liveAccountQualified":false,"productionQualified":false});
        if c.case.create().is_some(){
            value["mechanism"]=json!("same-original-git-push-create-v1");
            value["applyRequested"]=json!(c.case.apply_requested());
        }
        Some(value)
    }
}
impl Observation {
    pub(super) async fn git_push_tick(
        self: &Arc<Self>,
        _app: &tauri::AppHandle,
        document: &DocumentBinding,
        step: Step,
    ) {
        let Some(control) = &self.git_push else {
            self.fail_with("git-push-original-contract");
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
                    let v = r.git_push.as_mut().ok_or_else(invalid)?;
                    v.session = Some(session.id.clone());
                    v.connection_operation = Some(op.id.clone());
                    Some(Step::Connected)
                }
                Step::Connected => {
                    let s = document.github_connection_status();
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_push.as_mut().ok_or_else(invalid)?;
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
                                .is_none_or(|a| a.id != "831" || a.login != ACCOUNT)
                            || s.repository.value.as_ref().is_none_or(|a| {
                                a.id != "842" || a.full_name != control.case.coordinate()
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
                        .git_push
                        .as_mut()
                        .ok_or_else(invalid)?
                        .read_operation = Some(op.operation_id.clone());
                    Some(Step::ReadWait)
                }
                Step::ReadWait => {
                    let s = document.git_read_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    let f = r.fixture.git_push.as_ref().ok_or_else(invalid)?;
                    let read_matches = p.result["basis"] == "local-refs-no-fetch"
                        && p.result["observation"]["head"] == f.target()
                        && p.result["observation"]["branch"] == "refs/heads/main"
                        && if control.case.create().is_some(){create::tracking(&p.result["tracking"])}else{p.result["tracking"]["state"] == "complete"
                        && p.result["tracking"]["remote"] == "origin"
                        && p.result["tracking"]["localRef"] == "refs/remotes/origin/main"
                        && p.result["tracking"]["mergeRef"] == "refs/heads/main"
                        && p.result["tracking"]["head"] == f.base()
                        && p.result["tracking"]["ahead"] == 1
                        && p.result["tracking"]["behind"] == 0};
                    let v = r.git_push.as_mut().ok_or_else(invalid)?;
                    if v.read_operation.as_deref() != Some(&p.operation_id) {
                        return Err(invalid());
                    }
                    if matches!(p.phase, read::Phase::Starting | read::Phase::Running) {
                        None
                    } else {
                        if p.phase != read::Phase::Settled
                            || p.outcome != Some(read::Outcome::Ok)
                            || p.reason.is_some()
                            || !read_matches
                        {
                            return Err(invalid());
                        }
                        v.revision = Some(
                            p.result["observation"]["revision"]
                                .as_str()
                                .filter(|s| read::digest(s))
                                .ok_or_else(invalid)?
                                .into(),
                        );
                        v.reference_revision = Some(
                            p.result["referenceRevision"]
                                .as_str()
                                .filter(|s| read::digest(s))
                                .ok_or_else(invalid)?
                                .into(),
                        );
                        v.read = true;
                        Some(Step::Prepare)
                    }
                }
                Step::Prepare => {
                    let a = {
                        let r = self.record().ok_or_else(invalid)?;
                        let v = r.git_push.as_ref().ok_or_else(invalid)?;
                        push::Action {
                            kind: if control.case.create().is_some(){push::Kind::PushNewBranch}else{push::Kind::Push},
                            expected_revision: v.revision.clone().ok_or_else(invalid)?,
                            expected_reference_revision: v
                                .reference_revision
                                .clone()
                                .ok_or_else(invalid)?,
                            remote: if control.case.create().is_some(){None}else{Some("origin".into())},
                            local_ref: "refs/heads/main".into(),
                            remote_ref: "refs/heads/main".into(),
                            old_oid: if control.case.create().is_some(){push::new_branch::ZERO.into()}else{r
                                .fixture
                                .git_push
                                .as_ref()
                                .ok_or_else(invalid)?
                                .base()
                                .into()},
                            new_oid: r
                                .fixture
                                .git_push
                                .as_ref()
                                .ok_or_else(invalid)?
                                .target()
                                .into(),
                            connection_session_id: v.session.clone().ok_or_else(invalid)?,
                            expected_connection_revision: v.connection_revision,
                        }
                    };
                    let started = document.git_local_prepare(local::Prepare {
                        project_id: project,
                        expected_document_revision: document.git_local_status().document_revision,
                        action: local::Action::Push(a),
                    })?;
                    if !matches!(started.admission, read::Admission::Started)
                        || started.reason.is_some()
                    {
                        return Err(invalid());
                    }
                    self.record()
                        .ok_or_else(invalid)?
                        .git_push
                        .as_mut()
                        .ok_or_else(invalid)?
                        .active = Some(started.status.operation.ok_or_else(invalid)?);
                    Some(Step::PrepareWait)
                }
                Step::PrepareWait => {
                    let s = document.git_local_status();
                    let p = s.operation.ok_or_else(invalid)?;
                    let mut r = self.record().ok_or_else(invalid)?;
                    let v = r.git_push.as_mut().ok_or_else(invalid)?;
                    if !same(v.active.as_ref(), &p) {
                        return Err(invalid());
                    }
                    if matches!(p.stage, read::Phase::Starting | read::Phase::Running) {
                        None
                    } else if control.case==Case::Create(create::Case::Equal){
                        if !create::refused_prepare(create::Case::Equal,&p,s.review.is_none())
                            || !control.checked_sample(local::Phase::Prepare,&p){return Err(invalid())}
                        r.git_push.as_mut().ok_or_else(invalid)?.result=p.result;
                        Some(Step::Disconnect)
                    } else {
                        if p.stage != read::Phase::Settled
                            || p.outcome != Some(read::Outcome::Ok)
                            || p.reason.is_some()
                            || !control.checked_sample(local::Phase::Prepare, &p)
                        {
                            return Err(invalid());
                        }
                        let ready = s.review.ok_or_else(invalid)?;
                        let local::Review::Push(review) = &ready.review else {
                            return Err(invalid());
                        };
                        if review.repository != control.case.coordinate()
                            || review.account_id != "831"
                            || review.repository_id != "842"
                            || review.login != ACCOUNT
                        {
                            return Err(invalid());
                        }
                        let f = r.fixture.git_push.as_ref().ok_or_else(invalid)?;
                        if if control.case.create().is_some(){!create::review(review,f.base(),f.target())}else{review.head != f.target()
                            || review.expected_remote_oid != f.base()
                            || review.branch != "refs/heads/main"
                            || review.upstream_ref != "refs/heads/main"
                            || review.tracking_ref.as_deref() != Some("refs/remotes/origin/main")
                            || review.commits != [f.target()]
                            || !review.valid()}
                        {
                            return Err(invalid());
                        }
                        r.git_push.as_mut().ok_or_else(invalid)?.prepared = Some(ready);
                        Some(Step::Apply)
                    }
                }
                Step::Apply => {
                    let review = self
                        .record()
                        .and_then(|r| {
                            r.git_push
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
                        .git_push
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
                        .and_then(|r| r.git_push.as_ref()?.active.clone());
                    if !same(old.as_ref(), &p) {
                        return Err(invalid());
                    }
                    if matches!(
                        p.stage,
                        read::Phase::Starting | read::Phase::Running | read::Phase::Stopping
                    ) {
                        if control.held_case() && control.window(&p.operation_id) {
                            if !document.installed_git_push_pending(control, &p.operation_id)
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
                        if !expected_apply(control.case, &p) {
                            return Err(invalid());
                        }
                        let mut r = self.record().ok_or_else(invalid)?;
                        let v = r.git_push.as_mut().ok_or_else(invalid)?;
                        v.applied = true;
                        v.result = p.result;
                        Some(Step::Disconnect)
                    }
                }
                Step::Disconnect => {
                    let session = self
                        .record()
                        .and_then(|r| r.git_push.as_ref()?.session.clone())
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
                            .git_push
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
                            r.fixture.git_push.clone().ok_or_else(invalid)?,
                            r.fixture.root.clone(),
                            r.fixture.uid,
                            r.git_push.as_ref().ok_or_else(invalid)?.result.clone(),
                        )
                    };
                    fixture
                        .verify(&root, uid, control.case, &result)
                        .map_err(|_| invalid())?;
                    if !control.finish() {
                        return Err(invalid());
                    }
                    let mut r = self.record().ok_or_else(invalid)?;
                    if r.step != OuterStep::GitPush(step) || r.pending.is_some() {
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
                if r.step != OuterStep::GitPush(step) || r.pending.is_some() {
                    self.fail_with("git-push-original-contract");
                    return;
                }
                r.step = OuterStep::GitPush(next);
            }
            Ok(None) => {}
            _ => self.fail_with("git-push-original-contract"),
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

/// Only checks a projection already matched to the actual retired ticket.
/// It cannot turn a marker, this result, or process exit into a joined receipt.
fn expected_apply(case: Case, p: &local::Projection) -> bool {
    if p.phase != local::Phase::Apply || p.stage != read::Phase::Settled {
        return false;
    }
    match case {
        Case::Create(c) => create::expected_apply(c,p),
        Case::Pack => {
            p.outcome == Some(read::Outcome::Ok)
                && p.reason.is_none()
                && p.result["state"] == "succeeded"
                && p.result["effectPhase"] == "remote-returned"
                && p.result["settlement"] == "settled"
                && p.result["reason"].is_null()
                && p.result["intent"].is_object()
                && p.result["retainedPaths"] == json!([])
        }
        Case::Stale => {
            p.outcome == Some(read::Outcome::Ok)
                && p.reason.is_none()
                && p.result["state"] == "recovery-required"
                && p.result["effectPhase"] == "not-sent"
                && p.result["intent"].is_null()
                && p.result["reason"] == "target-changed"
                && p.result["settlement"] == "settled"
        }
        Case::Held => {
            // The original outer STOP may return a known cancellation, or the
            // actual joined core can retain its acknowledged-send recovery.
            // Neither is success. Missing native/IO closure never passes here.
            let cancelled = p.outcome == Some(read::Outcome::Cancelled)
                && p.reason.as_deref() == Some("authorization")
                && p.result.is_null();
            let recovery = p.outcome == Some(read::Outcome::Ok)
                && p.reason.is_none()
                && p.result["state"] == "recovery-required"
                && p.result["settlement"] == "settled"
                && p.result["intent"].is_object()
                && p.result["effectPhase"] == "send-consumed"
                && matches!(
                    p.result["reason"].as_str(),
                    Some("recovery-required" | "authorization" | "response-invalid")
                );
            cancelled || recovery
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection() -> local::Projection {
        local::Projection {
            operation_id: "git-local-2".into(),
            context: read::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "a".repeat(64),
            },
            phase: local::Phase::Apply,
            action: local::Action::Push(push::tests::action()).public(),
            stage: read::Phase::Settled,
            outcome: Some(read::Outcome::Ok),
            reason: None,
            result: json!({"state":"succeeded","effectPhase":"remote-returned",
                "settlement":"settled","reason":null,"intent":{},"retainedPaths":[]}),
        }
    }

    #[test]
    fn push_case_results_never_accept_unknown_or_send_refusal_as_success() {
        // These are DATA comparisons only; the real caller first requires the
        // same original retired ticket and its checked_sample, not this object.
        let mut p = projection();
        assert!(expected_apply(Case::Pack, &p));
        assert!(!expected_apply(Case::Stale, &p));
        assert!(!expected_apply(Case::Held, &p));
        p.phase = local::Phase::Prepare;
        assert!(!expected_apply(Case::Pack, &p));
        p.phase = local::Phase::Apply;
        p.result = json!({"state":"recovery-required","effectPhase":"not-sent",
            "settlement":"settled","reason":"target-changed","intent":null});
        assert!(expected_apply(Case::Stale, &p));
        assert!(!expected_apply(Case::Pack, &p));
        p.result = json!({"state":"recovery-required","effectPhase":"send-consumed",
            "settlement":"settled","reason":"response-invalid","intent":{}});
        assert!(expected_apply(Case::Held, &p));
        assert!(!expected_apply(Case::Stale, &p));
        p.outcome = Some(read::Outcome::Cancelled);
        p.reason = Some("authorization".into());
        p.result = Value::Null;
        assert!(expected_apply(Case::Held, &p));
        p.outcome = Some(read::Outcome::CleanupUnknown);
        assert!(Case::ALL.into_iter().all(|c| !expected_apply(c, &p)));
        p.outcome = Some(read::Outcome::Cancelled);
        p.stage = read::Phase::Stopping;
        assert!(Case::ALL.into_iter().all(|c| !expected_apply(c, &p)));
    }

    #[test]
    fn push_projection_requires_original_id_context_phase_and_action() {
        let old = projection();
        let mut now = old.clone();
        assert!(same(Some(&old), &now));
        assert!(!same(None, &now));
        now.operation_id.push('x');
        assert!(!same(Some(&old), &now));
        now = old.clone();
        now.context.generation += 1;
        assert!(!same(Some(&old), &now));
        now = old.clone();
        now.context.revision = "b".repeat(64);
        assert!(!same(Some(&old), &now));
        now = old.clone();
        now.phase = local::Phase::Prepare;
        assert!(!same(Some(&old), &now));
        now = old.clone();
        let local::PublicAction::Push(a) = &mut now.action else {
            panic!("test action")
        };
        a.old_oid = "3".repeat(40);
        assert!(!same(Some(&old), &now));
    }

    #[test]
    fn push_marker_and_data_without_original_registration_cannot_settle_or_stop() {
        // No OS/Observation/Document/Runtime is constructed. In particular,
        // public case/paths and marker-shaped DATA do not bind those originals.
        let c = Control {
            case: Case::Held,
            project: "/unbound-push-fixture".into(),
            application: "/unbound-push-application".into(),
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            tool: OnceLock::new(),
            data: OnceLock::new(),
            trace: Mutex::new(Trace::default()),
        };
        let document = Arc::new(());
        assert!(!c.registered(&document));
        assert!(!c.bound(&document));
        assert!(!c.live());
        assert!(!c.marker("git-local-2"));
        assert!(!c.producer_pending("git-local-2"));
        assert!(!c.window("git-local-2"));
        assert!(!c.stop_entered("git-local-2"));
        assert!(!c.finish());
        assert!(!c.completed());
        assert!(c.retained_bytes().is_none());
        let mut record = Record::default();
        assert!(!record.final_originals(&c, 2, true));
        assert!(record.report(&c).is_none());
    }
}
