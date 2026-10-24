//! Two fixed local Git installed-CLI journeys in the existing observer.
//! This comparison control grants no runtime/profile, Connection, source,
//! Candidate/ACK or finality authority. Both Reads, Prepare and Apply use the
//! ordinary Git owners; CLI caller and history returns are checked separately.
use super::{Case as OuterCase, DocumentBinding, GitReadCheck as ReadCheck, GitReadFailureSample, Observation, Step as OuterStep};
use crate::{
    error::BridgeError, git_local_protocol as local, git_read_protocol as read,
    service_git_protocol as wire,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock, Weak,
    },
    time::Instant,
};
#[path = "installed_shell_observation_macos_git_cli_fixture.rs"]
mod fixture;
pub(super) use fixture::Fixture;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    Index,
    Branch,
}
impl Case {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Index => "git-index-cli",
            Self::Branch => "git-branch-cli",
        }
    }
    pub(super) fn parse(s: &str) -> Option<Self> {
        match s {
            "git-index-cli" => Some(Self::Index),
            "git-branch-cli" => Some(Self::Branch),
            _ => None,
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::Index => "git-index-cli-native",
            Self::Branch => "git-branch-cli-native",
        }
    }
    pub(super) fn calls(self) -> usize {
        if self == Self::Index {
            8
        } else {
            5
        }
    }
    pub(super) fn rows(self) -> usize {
        if self == Self::Index {
            5
        } else {
            3
        }
    }
}
pub(super) fn selected(role: Option<&str>, scope: Option<&str>, arm: bool) -> bool {
    arm && role == Some("installed-shell-observation") && scope == Some("git-native")
}
pub(super) fn admitted() -> bool {
    selected(
        option_env!("MRK_MACOS_PACKAGE_ROLE"),
        option_env!("MRK_MACOS_NATIVE_SCOPE"),
        cfg!(target_arch = "aarch64"),
    )
}
pub(crate) const SECONDS: u64 = 120;
// The original getters return owned projections. At most one read/local
// result and one local Prepared coexist here. Use their existing decoded
// bounds, not encoded-byte == heap. The separate fixed MiB covers both phase
// files/parsing, <=64KiB fixture reads, small MAIN/status conversions, outer
// observer comparison cells and temporary clones. No original debt is removed.
const COMPARISON_BACKING: usize = read::RESULT_BACKING + local::REVIEW_BACKING + 1024 * 1024;

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
    Some(support(home)?.join(format!("mrk-macos-aqua-{s}-{r}-{a}-{}", case.scope())))
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
}
impl Control {
    pub(super) fn new(project: &Path, uid: u32, case: Case) -> Result<Arc<Self>, ()> {
        if !admitted() || uid == 0 {
            return Err(());
        }
        let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map_err(|_| ())?
            .ok_or(())?;
        if u.uid.as_raw() != uid
            || project != fixture_root(&u.dir, case).ok_or(())?.join(case.name())
        {
            return Err(());
        }
        Ok(Arc::new(Self {
            case,
            project: project.to_owned(),
            application: super::cli::application_for(uid, case.name()).ok_or(())?,
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            complete: AtomicBool::new(false),
        }))
    }
    fn observation(&self) -> Option<Arc<Observation>> {
        self.original.get()?.upgrade().filter(|q| {
            q.case == OuterCase::GitCli(self.case)
                && q.git_cli
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
    pub(crate) fn case(&self) -> Case {
        self.case
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
            .checked_add(COMPARISON_BACKING)?
            .checked_add(self.project.capacity())?
            .checked_add(self.application.capacity())?
            .checked_add(4 * std::mem::size_of::<usize>())?;
        let q = self.observation()?;
        let r = q.record.try_lock().ok()?;
        n.checked_add(r.git_cli.as_ref()?.retained_bytes()?)?
            .checked_add(
                r.fixture
                    .git_cli
                    .as_ref()?
                    .retained_bytes()?
                    .checked_mul(2)?,
            )
    }
    fn finish(&self, r: &Record) -> bool {
        self.live()
            && r.read_count == 2
            && r.prepared.is_some()
            && r.terminal.is_some()
            && r.checked
            && r.revoked
            && r.driver_done
            && r.files.closed()
            && r.after.is_some()
            && (self.case != Case::Index || r.reallowed && r.empty_revoke)
            && !r.normal_quit
            && !self.complete.swap(true, Ordering::SeqCst)
    }
    fn attach(
        self: &Arc<Self>,
        q: &Arc<Observation>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if q.case != OuterCase::GitCli(self.case)
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
        document.register_installed_macos_git_cli(Registration {
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
    pub(crate) fn git_cli_application(&self) -> Option<&Path> {
        self.git_cli.as_ref().map(|c| c.application())
    }
    pub(crate) fn attach_git_cli(
        self: &Arc<Self>,
        document: &DocumentBinding,
    ) -> Result<(), BridgeError> {
        if let Some(c) = &self.git_cli {
            c.attach(self, document)?
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Read,
    ReadWait,
    Allow,
    Submitted,
    Prepared,
    Started,
    Terminal,
    Checked,
    Revoke,
    Denied,
    Done,
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
struct Prepared {
    operation: String,
    review: String,
    digest: String,
    status: String,
}
#[derive(Clone)]
struct Terminal {
    operation: String,
    status: String,
}
pub(super) struct Record {
    files: super::cli::fixture::Files,
    reads: Vec<ReadOriginal>,
    read_count: u8,
    project: Option<crate::service_protocol::Id>,
    grant: Option<crate::service_protocol::Id>,
    origin: Option<wire::Query>,
    revision: Option<String>,
    references: Option<String>,
    selection_hash: Option<String>,
    prepared: Option<Prepared>,
    terminal: Option<Terminal>,
    after: Option<fixture::After>,
    empty_revoke: bool,
    checked: bool,
    revoked: bool,
    reallowed: bool,
    driver_done: bool,
    normal_quit: bool,
    host: Option<usize>,
}
impl Record {
    pub(super) fn new(root: &Path, uid: u32, case: Case) -> Result<Self, ()> {
        Ok(Self {
            files: super::cli::fixture::Files::capture_git(root, uid, case)?,
            reads: Vec::new(),
            read_count: 0,
            project: None,
            grant: None,
            origin: None,
            revision: None,
            references: None,
            selection_hash: None,
            prepared: None,
            terminal: None,
            after: None,
            empty_revoke: false,
            checked: false,
            revoked: false,
            reallowed: false,
            driver_done: false,
            normal_quit: false,
            host: None,
        })
    }
    fn retained_bytes(&self) -> Option<usize> {
        // Actual capacities for the two retained original comparisons. The
        // Control debits the existing projection bounds plus fixed comparison
        // backing; no native/source/Entry/history quote is credited.
        let mut n = std::mem::size_of::<Self>()
            .checked_add(self.files.retained_bytes()?)?
            .checked_add(
                self.reads
                    .capacity()
                    .checked_mul(std::mem::size_of::<ReadOriginal>())?,
            )?
            .checked_add(5 * 32)?;
        for p in &self.reads {
            for s in [&p.id, &p.context.project_id, &p.context.revision] {
                n = n.checked_add(s.capacity())?;
            }
            n = n.checked_add(
                p.action
                    .paths
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())?,
            )?;
            for s in &p.action.paths {
                n = n.checked_add(s.capacity())?;
            }
            if let Some(s) = &p.action.expected_revision {
                n = n.checked_add(s.capacity())?;
            }
        }
        for s in [&self.revision, &self.references, &self.selection_hash]
            .into_iter()
            .flatten()
        {
            n = n.checked_add(s.capacity())?;
        }
        if let Some(p) = &self.prepared {
            for s in [&p.operation, &p.review, &p.digest, &p.status] {
                n = n.checked_add(s.capacity())?;
            }
        }
        if let Some(p) = &self.terminal {
            for s in [&p.operation, &p.status] {
                n = n.checked_add(s.capacity())?;
            }
        }
        if let Some(a) = &self.after {
            n = n.checked_add(a.retained_bytes()?.checked_mul(2)?)?;
        }
        Some(n)
    }
    pub(super) fn final_originals(&mut self, c: &Control, id: u32, finality: bool) -> bool {
        if self.normal_quit
            || !c.completed()
            || !finality
            || id != 2
            || self.read_count != 2
            || !self.driver_done
            || !self.files.closed()
            || self.after.is_none()
        {
            return false;
        }
        self.normal_quit = true;
        true
    }
    pub(super) fn report(&self, c: &Control) -> Option<Value> {
        if !self.normal_quit
            || !c.completed()
            || !self.files.closed()
            || self.host != Some(c.case.calls())
        {
            return None;
        }
        let p = self.prepared.as_ref()?;
        let t = self.terminal.as_ref()?;
        Some(
            json!({"mechanism":"same-original-local-git-cli-v1","case":c.case.name(),"origin":self.origin.as_ref()?,
            "prepareOperationId":p.operation,"reviewId":p.review,"applyOperationId":t.operation,"statusSha256":t.status,
            "readOriginalsJoined":2,"prepareOriginalsJoined":1,"applyOriginalsJoined":1,"hostWorkersJoined":self.host?,
            "normalQuitOriginal":2,"allOriginalsSettled":true,"phaseOriginalsClosed":true,"projectDeltaCompared":true,
            "emptyRevokeRefused":self.empty_revoke,"lateStopOnly":c.case==Case::Index,"readReallowedOnly":self.reallowed,
            "networkRequested":false,"bootstrapOverride":false,"productionQualified":false}),
        )
    }
}
// Only this closed case can select the extra readback. It retains comparisons
// from the SAME completed originals; no file IO occurs under the Record lock.
pub(super) struct FinalReadback {
    case: Case,
    root: PathBuf,
    uid: u32,
    fixture: Fixture,
    after: fixture::After,
}
impl FinalReadback {
    fn fixture_shape(f: &super::Fixture) -> bool {
        // Exclusion only: capture/matches still require the SAME GitCli
        // fixture, result, After and exited originals. The legitimate shared
        // app/config/release/ignore facts must not be excluded here.
        f.untouched.is_none()
            && f.ios.is_none()
            && f.project_fields.is_none()
            && f.recovery.is_none()
            && f.local_edits.is_none()
            && f.checks.is_none()
            && f.identity.is_none()
            && f.tools.is_none()
            && f.git_fetch.is_none()
            && f.git_push.is_none()
            && f.git_upstream.is_none()
            && !f.written
            && !f.mutated
    }
    pub(super) fn capture(r: &super::Record, c: &Control) -> Option<Self> {
        let v = r.git_cli.as_ref()?;
        if !Self::fixture_shape(&r.fixture)
            || !r.actual_exit
            || !r.originals_final
            || !r.relay_joined
            || r.step != OuterStep::Exit
            || r.pending.is_some()
            || v.report(c).is_none()
        {
            return None;
        }
        Some(Self {
            case: c.case,
            root: r.fixture.root.clone(),
            uid: r.fixture.uid,
            fixture: r.fixture.git_cli.clone()?,
            after: v.after.clone()?,
        })
    }
    pub(super) fn verify(&self) -> Result<(), ()> {
        self.fixture
            .verify_unchanged(&self.root, self.uid, &self.after)
    }
    pub(super) fn matches(&self, r: &super::Record, c: &Control) -> bool {
        Self::fixture_shape(&r.fixture)
            && self.case == c.case
            && self.root == r.fixture.root
            && self.uid == r.fixture.uid
            && r.fixture.git_cli.as_ref() == Some(&self.fixture)
            && r.git_cli
                .as_ref()
                .is_some_and(|v| v.after.as_ref() == Some(&self.after) && v.report(c).is_some())
            && r.actual_exit
            && r.originals_final
            && r.relay_joined
            && r.step == OuterStep::Exit
            && r.pending.is_none()
    }
}
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k)))
}
fn value(v: &impl serde::Serialize) -> Result<Value, BridgeError> {
    let raw = crate::edit_protocol::bounded(v, 8192)?;
    crate::protocol::strict_json(&raw)
}
fn canonical(mut v: Value) -> Result<String, BridgeError> {
    v.sort_all_objects();
    Ok(super::digest(&crate::edit_protocol::bounded(&v, 8192)?))
}
fn fixed_action(case: Case, revision: &str, references: &str) -> local::PublicAction {
    match case {
        Case::Index => local::PublicAction::Files(local::PublicFileAction {
            kind: local::Kind::Stage,
            expected_revision: revision.into(),
            paths: vec!["untracked.txt".into()],
        }),
        Case::Branch => local::PublicAction::Branch(crate::git_branch_protocol::Action {
            kind: crate::git_branch_protocol::Kind::Create,
            expected_revision: revision.into(),
            expected_reference_revision: references.into(),
            name: "observer-local".into(),
        }),
    }
}
fn read_result(p: &read::Projection, head: &str, case: Case, after: bool, result_valid: &mut Option<bool>) -> Result<(), ReadCheck> {
    if !super::git_read_wait_terminal(p)? { return Err(ReadCheck::TerminalPhase); }
    // The same existing schema validation runs once, only after real terminal
    // checks. Pending/refused states never acquire a diagnostic validation.
    let valid = read::validate_result(&p.action, &p.result).is_ok();
    *result_valid = Some(valid);
    if !valid { return Err(ReadCheck::ResultSchema); }
    if p.result["basis"] == "local-refs-no-fetch"
        && p.result["observation"]["head"] == head
        && p.result["observation"]["branch"] == "refs/heads/main"
        && p.result["observation"]["restrictions"] == json!([])
        && p.result["observation"]["remotes"] == json!([])
        && p.result["tracking"]
            == json!({"state":"not-configured","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null})
        && p.result["observation"]["changes"]
            == json!([{"path":"untracked.txt","index":if after&&case==Case::Index{"A"}else{"?"},
            "worktree":if after&&case==Case::Index{" "}else{"?"},"kind":"file","conflict":false}])
    { Ok(()) } else { Err(ReadCheck::FixtureComparison) }
}
impl Observation {
    fn git_cli_access(&self, d: &DocumentBinding, case: Case) -> Result<Value, BridgeError> {
        match case {
            Case::Index => value(&d.agent_git_index_access("main")?),
            Case::Branch => value(&d.agent_git_repository_access("main")?),
        }
    }
    fn git_cli_revoke(&self, d: &DocumentBinding, case: Case) -> Result<Value, BridgeError> {
        match case {
            Case::Index => value(&d.revoke_agent_git_index("main")?),
            Case::Branch => value(&d.revoke_agent_git_repository("main")?),
        }
    }
    fn git_cli_allow(
        &self,
        d: &DocumentBinding,
        case: Case,
        raw: &Value,
    ) -> Result<Value, BridgeError> {
        let bytes = crate::edit_protocol::bounded(raw, 8192)?;
        match case {
            Case::Index => value(&d.allow_agent_git_index(
                "main",
                crate::asset_session::agent_git_index::decode_allow(&bytes)?,
            )?),
            Case::Branch => value(&d.allow_agent_git_repository(
                "main",
                crate::asset_session::agent_git_index::decode_repository_allow(&bytes)?,
            )?),
        }
    }
    pub(super) async fn git_cli_tick(
        self: &Arc<Self>,
        _app: &tauri::AppHandle,
        document: &DocumentBinding,
        step: Step,
    ) {
        let bad = BridgeError::invalid;
        let outcome:Result<Option<Step>,BridgeError>=async {
            let c=self.git_cli.as_ref().ok_or_else(bad)?;
            if !c.live()||self.case!=OuterCase::GitCli(c.case){return Err(bad());}
            let project=self.record().and_then(|r|r.project.as_ref().map(|p|p.id.clone())).ok_or_else(bad)?;
            Ok(match step {
                Step::Read=>{
                    {let r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_ref().ok_or_else(bad)?;
                        if v.read_count>=2||v.reads.len()!=usize::from(v.read_count)||v.terminal.is_some()!=(v.read_count==1){return Err(bad());}}
                    let result=document.git_read_start(read::Start{project_id:project.clone(),expected_document_revision:document.git_read_status().document_revision,
                        action:read::Action{kind:read::Kind::Observe,expected_revision:None,paths:Vec::new(),staged:false}})?;
                    if !matches!(result.admission,read::Admission::Started)||result.reason.is_some(){return Err(bad());}
                    let p=result.status.operation.ok_or_else(bad)?;
                    if p.context.project_id!=project||p.action.kind!=read::Kind::Observe{return Err(bad());}
                    let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    if v.reads.iter().any(|o|o.id==p.operation_id){return Err(bad());}
                    v.reads.push(ReadOriginal::capture(&p));Some(Step::ReadWait)
                },
                Step::ReadWait=>{
                    let status=document.git_read_status();
                    if status.operation.is_none(){
                        self.fail_git_read_missing(OuterStep::GitCli(step),"git-cli-original-contract");
                        return Err(bad());
                    }
                    let mut r=self.record().ok_or_else(bad)?;
                    let mut result_valid=None;
                    let checked=(||{
                        let p=status.operation.as_ref().ok_or(ReadCheck::MissingOperation)?;
                        let head=r.fixture.git_cli.as_ref().ok_or(ReadCheck::MissingFixture)?.target().to_owned();
                        let v=r.git_cli.as_mut().ok_or(ReadCheck::MissingOriginal)?;
                        let original=v.reads.last().ok_or(ReadCheck::MissingOriginal)?;
                        if !original.matches(p){return Err(ReadCheck::OriginalMismatch);}
                        if !super::git_read_wait_terminal(p)?{return Ok(None);}
                        read_result(p,&head,c.case,v.read_count==1,&mut result_valid)?;
                        if v.read_count==0 {
                            v.revision=Some(p.result["observation"]["revision"].as_str().ok_or(ReadCheck::ResultSchema)?.into());
                            v.references=Some(p.result["referenceRevision"].as_str().ok_or(ReadCheck::ReferenceRevision)?.into());
                        }else if (c.case==Case::Branch&&p.result["referenceRevision"].as_str()==v.references.as_deref())
                            ||(c.case==Case::Index&&p.result["referenceRevision"].as_str()!=v.references.as_deref()){return Err(ReadCheck::ReferenceRevision);}
                        v.read_count+=1;Ok(Some(if v.read_count==1{Step::Allow}else{Step::Revoke}))
                    })();
                    match checked {
                        Ok(next)=>next,
                        Err(check)=>{
                            let sample=GitReadFailureSample::capture(OuterStep::GitCli(step),status.operation.as_ref(),check,result_valid);
                            self.fail_git_read_wait(&mut r,"git-cli-original-contract",sample);
                            return Err(bad());
                        }
                    }
                },
                Step::Allow=>{
                    let path=self.record().and_then(|r|r.git_cli.as_ref()?.files.application().ok()).ok_or_else(bad)?;
                    let checked=document.application_read_status()?;
                    let read=document.allow_application_read(&project,checked.permission_revision,&path).await?;
                    if !read.enabled||read.remaining_ms==0||read.project_ids.len()!=1{return Err(bad());}
                    let initial=self.git_cli_access(document,c.case)?;
                    if initial["enabled"]!=false||initial["grantId"]!=Value::Null{return Err(bad());}
                    let document_revision=document.git_read_status().document_revision;
                    let mut args={let r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_ref().ok_or_else(bad)?;
                        let rev=v.revision.as_deref().ok_or_else(bad)?;let refs=v.references.as_deref().ok_or_else(bad)?;
                        let mut a=json!({"projectId":project,"expectedDocumentRevision":document_revision,
                            "expectedPermissionRevision":initial["permissionRevision"],"readOperationId":v.reads.first().ok_or_else(bad)?.id});
                        if c.case==Case::Index {a["action"]=json!("stage");a["paths"]=json!(["untracked.txt"]);a["consentVersion"]=json!(wire::CONSENT);}
                        else {a["action"]=value(&crate::service_git_repository_protocol::Action::BranchCreate{
                            expected_revision:rev.into(),expected_reference_revision:refs.into(),name:"observer-local".into()})?;
                            a["consentVersion"]=json!(crate::service_git_repository_protocol::CONSENT);}
                        a};
                    if c.case==Case::Index {
                        let off=self.git_cli_revoke(document,c.case)?;
                        if off["enabled"]!=false||off["permissionRevision"]==initial["permissionRevision"]{return Err(bad());}
                        let refused=self.git_cli_allow(document,c.case,&args);
                        if !matches!(refused,Err(ref e) if *e==crate::asset_session::application_service::public_error(crate::service_protocol::Error::Conflict))
                            ||self.git_cli_access(document,c.case)?["enabled"]!=false{return Err(bad());}
                        let fresh=self.git_cli_access(document,c.case)?;
                        args["expectedPermissionRevision"]=fresh["permissionRevision"].clone();
                    }
                    let granted=self.git_cli_allow(document,c.case,&args)?;
                    let id=read.project_ids[0].clone();
                    if granted["enabled"]!=true||granted["consumed"]!=false||granted["projectId"]!=json!(id)
                        ||!granted["remainingMs"].as_u64().is_some_and(|n|n>0){return Err(bad());}
                    let grant=serde_json::from_value(granted["grantId"].clone()).map_err(|_|bad())?;
                    let hash=if c.case==Case::Index {&granted["selection"]["summary"]["selectionSha256"]}else{&granted["selection"]["selectionSha256"]};
                    let hash=hash.as_str().filter(|s|read::digest(s)).ok_or_else(bad)?.to_owned();
                    let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    if v.project.is_some()||v.grant.is_some(){return Err(bad());}
                    v.project=Some(id.clone());v.grant=Some(grant);v.selection_hash=Some(hash.clone());v.empty_revoke=c.case==Case::Index;
                    v.files.send(&json!({"phase":"allowed","projectId":id,"grantId":v.grant,"repositoryRevision":v.revision,
                        "referenceRevision":v.references,"selectionSha256":hash})).map_err(|_|bad())?;
                    Some(Step::Submitted)
                },
                Step::Submitted=>{
                    let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    if let Some(row)=v.files.poll(0,"submitted").map_err(|_|bad())? {
                        if !keys(&row,&["phase","origin"])||v.origin.is_some(){return Err(bad());}
                        let o:wire::Query=serde_json::from_value(row["origin"].clone()).map_err(|_|bad())?;
                        if Some(&o.project_id)!=v.project.as_ref(){return Err(bad());}
                        v.origin=Some(o);Some(Step::Prepared)
                    }else{None}
                },
                Step::Prepared|Step::Terminal=>{
                    let apply=step==Step::Terminal;
                    let origin=self.record().and_then(|r|r.git_cli.as_ref()?.origin.clone()).ok_or_else(bad)?;
                    // Positive private retirement + Claim::returned + matching
                    // history ACK, not phase data or the public Row alone.
                    let Some(status)=document.installed_git_cli_returned(&project,&origin,apply)? else{return Ok(None)};
                    let current=document.git_local_status();
                    let consumed=if !apply {Some(self.git_cli_access(document,c.case)?)}else{None};
                    let p=current.operation.ok_or_else(bad)?;
                    let mut r=self.record().ok_or_else(bad)?;
                    let head=r.fixture.git_cli.as_ref().ok_or_else(bad)?.target().to_owned();
                    let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    let expected=fixed_action(c.case,v.revision.as_deref().ok_or_else(bad)?,v.references.as_deref().ok_or_else(bad)?);
                    let first=v.reads.first().ok_or_else(bad)?;
                    if p.context.project_id!=project||p.context.generation!=first.context.generation||p.action!=expected
                        ||p.stage!=read::Phase::Settled||p.outcome!=Some(read::Outcome::Ok)||p.reason.is_some()
                        ||status["grantId"]!=json!(v.grant)||status["origin"]!=json!(origin){return Err(bad());}
                    if !apply {
                        let consumed=consumed.ok_or_else(bad)?;
                        if consumed["enabled"]!=false||consumed["consumed"]!=true
                            ||consumed["grantId"]!=json!(v.grant)||consumed["projectId"]!=json!(v.project){return Err(bad());}
                        let prepared=current.review.ok_or_else(bad)?;
                        if p.phase!=local::Phase::Prepare||status["prepareOperationId"]!=p.operation_id
                            ||prepared.context!=p.context||prepared.action!=expected||!prepared.review.valid()
                            ||prepared.review.head()!=Some(head.as_str())||prepared.review.branch()!=Some("refs/heads/main")
                            ||prepared.review.expected_revision()!=v.revision.as_deref().ok_or_else(bad)?
                            ||status["review"]["reviewId"]!=prepared.review_id||status["review"]["reviewDigest"]!=prepared.review.review_digest()
                            ||status["review"]["expectedIndex"].as_str()!=prepared.review.expected_index(){return Err(bad());}
                        let done=Prepared{operation:p.operation_id,review:prepared.review_id,digest:prepared.review.review_digest().into(),status:canonical(status)?};
                        v.files.send(&json!({"phase":"prepared","prepareOperationId":done.operation,"reviewId":done.review,"reviewDigest":done.digest,"statusSha256":done.status})).map_err(|_|bad())?;
                        v.prepared=Some(done);Some(Step::Started)
                    } else {
                        let prepared=v.prepared.as_ref().ok_or_else(bad)?;
                        if p.phase!=local::Phase::Apply||current.review.is_some()||status["applyOperationId"]!=p.operation_id
                            ||status["prepareOperationId"]!=prepared.operation||p.operation_id==prepared.operation{return Err(bad());}
                        let done=Terminal{operation:p.operation_id,status:canonical(status)?};
                        v.files.send(&json!({"phase":"terminal","applyOperationId":done.operation,"statusSha256":done.status})).map_err(|_|bad())?;
                        v.terminal=Some(done);Some(Step::Checked)
                    }
                },
                Step::Started=>{
                    let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    if let Some(row)=v.files.poll(1,"started").map_err(|_|bad())? {
                        let p=v.prepared.as_ref().ok_or_else(bad)?;
                        if row!=json!({"phase":"started","origin":v.origin,"prepareOperationId":p.operation,"reviewId":p.review}){return Err(bad());}
                        Some(Step::Terminal)
                    }else{None}
                },
                Step::Checked=>{
                    let row={let mut r=self.record().ok_or_else(bad)?;r.git_cli.as_mut().ok_or_else(bad)?.files.poll(2,if c.case==Case::Index{"checked"}else{"done"}).map_err(|_|bad())?};
                    if let Some(row)=row {
                        let (origin,hash)={let r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_ref().ok_or_else(bad)?;
                            (v.origin.clone().ok_or_else(bad)?,v.terminal.as_ref().ok_or_else(bad)?.status.clone())};
                        if row!=json!({"phase":if c.case==Case::Index{"checked"}else{"done"},"origin":origin,"statusSha256":hash})
                            ||canonical(document.installed_git_cli_returned(&project,&origin,true)?.ok_or_else(bad)?)?!=hash{return Err(bad());}
                        let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                        v.checked=true;v.driver_done=c.case==Case::Branch;Some(Step::Read)
                    }else{None}
                },
                Step::Revoke=>{
                    let off=self.git_cli_revoke(document,c.case)?;let read=document.revoke_application_read()?;
                    if off["enabled"]!=false||read.enabled{return Err(bad());}
                    let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;v.revoked=true;
                    if c.case==Case::Index{v.files.send(&json!({"phase":"revoked"})).map_err(|_|bad())?;Some(Step::Denied)}else{Some(Step::Finish)}
                },
                Step::Denied=>{
                    let row={let mut r=self.record().ok_or_else(bad)?;r.git_cli.as_mut().ok_or_else(bad)?.files.poll(3,"denied").map_err(|_|bad())?};
                    if let Some(row)=row {
                        if row!=json!({"phase":"denied"})||c.case!=Case::Index{return Err(bad());}
                        let path=self.record().and_then(|r|r.git_cli.as_ref()?.files.application().ok()).ok_or_else(bad)?;
                        let checked=document.application_read_status()?;
                        let read=document.allow_application_read(&project,checked.permission_revision,&path).await?;
                        if !read.enabled||read.remaining_ms==0||read.project_ids.len()!=1||self.git_cli_access(document,c.case)?["enabled"]!=false{return Err(bad());}
                        let mut r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_mut().ok_or_else(bad)?;
                        if read.project_ids.first()!=v.project.as_ref(){return Err(bad());}
                        v.reallowed=true;v.files.send(&json!({"phase":"reallowed"})).map_err(|_|bad())?;Some(Step::Done)
                    }else{None}
                },
                Step::Done=>{
                    let row={let mut r=self.record().ok_or_else(bad)?;r.git_cli.as_mut().ok_or_else(bad)?.files.poll(4,"done").map_err(|_|bad())?};
                    if let Some(row)=row {
                        let (o,hash)={let r=self.record().ok_or_else(bad)?;let v=r.git_cli.as_ref().ok_or_else(bad)?;
                            (v.origin.clone().ok_or_else(bad)?,v.terminal.as_ref().ok_or_else(bad)?.status.clone())};
                        if row!=json!({"phase":"done","origin":o,"statusSha256":hash})
                            ||canonical(document.installed_git_cli_returned(&project,&o,true)?.ok_or_else(bad)?)?!=hash{return Err(bad());}
                        let mut r=self.record().ok_or_else(bad)?;r.git_cli.as_mut().ok_or_else(bad)?.driver_done=true;Some(Step::Finish)
                    }else{None}
                },
                Step::Finish=>{
                    // No Record/Doc guard spans these independent file calls.
                    let (fixture,uid)={let r=self.record().ok_or_else(bad)?;(r.fixture.git_cli.clone().ok_or_else(bad)?,r.fixture.uid)};
                    let after=fixture.after(&self.project_path,uid).map_err(|_|bad())?;
                    fixture.verify_unchanged(&self.project_path,uid,&after).map_err(|_|bad())?;
                    let mut r=self.record().ok_or_else(bad)?;
                    if r.step!=OuterStep::GitCli(step)||r.pending.is_some(){return Err(bad());}
                    let v=r.git_cli.as_mut().ok_or_else(bad)?;
                    v.after=Some(after);v.files.close().map_err(|_|bad())?;
                    if !c.finish(v){return Err(bad());}
                    r.file_readback=true;r.step=OuterStep::Close;None
                },
            })
        }.await;
        match outcome {
            Ok(Some(next)) if self.timely() => {
                if let Some(mut r) = self.record() {
                    if r.step == OuterStep::GitCli(step) && r.pending.is_none() {
                        r.step = OuterStep::GitCli(next)
                    } else {
                        self.fail_with("git-cli-original-contract");
                    }
                }
            }
            Ok(None) => {}
            Err(_) => self.fail_with("git-cli-original-contract"),
            Ok(Some(_)) => self.fail_with("git-cli-original-contract"),
        }
    }
    pub(super) fn git_cli_host_return(
        &self,
        report: &crate::application_service_host::HostShutdownReport,
    ) -> bool {
        let Some(c) = &self.git_cli else { return false };
        let Some(mut r) = self.record() else {
            return false;
        };
        if self.failed.load(Ordering::SeqCst) && !c.completed() {
            // The exit observer already requires actual Document quit, the
            // original relay join and this returned Host shutdown. A failed
            // first ReadWait precedes Allow: no CLI work was admitted, so its
            // unstarted success journey cannot be a failure-exit obligation.
            if self.case != OuterCase::GitCli(c.case)
                || r.step != OuterStep::GitCli(Step::ReadWait)
                || r.pending.is_some()
                || !r.relay_joined
                || !self.open_custody.try_lock().map(|v| v.is_none()).unwrap_or(false)
                || !report.settled()
                || !report.failures.is_empty()
                || report.workers_joined.is_some()
                || Instant::now() >= self.end
            {
                return false;
            }
            let Some(v) = r.git_cli.as_mut() else { return false };
            if v.read_count != 0
                || v.reads.len() != 1
                || v.project.is_some()
                || v.grant.is_some()
                || v.origin.is_some()
                || v.revision.is_some()
                || v.references.is_some()
                || v.selection_hash.is_some()
                || v.prepared.is_some()
                || v.terminal.is_some()
                || v.after.is_some()
                || v.empty_revoke || v.checked || v.revoked || v.reallowed
                || v.driver_done || v.normal_quit || v.host.is_some()
            {
                return false;
            }
            // These are still real retained originals. Use their existing
            // sole POST/close, never a Drop, retry, fresh clock or success flag.
            return v.files.close().is_ok() && v.files.closed() && Instant::now() < self.end;
        }
        let Some(v) = r.git_cli.as_mut() else {
            return false;
        };
        if !c.completed()
            || !v.driver_done
            || !v.files.closed()
            || v.host.is_some()
            || !report.settled()
            || !report.failures.is_empty()
            || report.workers_joined != Some(c.case.calls())
        {
            self.fail_with("git-cli-original-contract");
            return false;
        }
        v.host = report.workers_joined;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_cli_cases_keep_exact_local_actions_and_combined_image_only() {
        for (case, name, scope, calls, rows) in [
            (Case::Index, "git-index-cli", "git-index-cli-native", 8, 5),
            (
                Case::Branch,
                "git-branch-cli",
                "git-branch-cli-native",
                5,
                3,
            ),
        ] {
            assert_eq!(Case::parse(name), Some(case));
            assert_eq!(
                (case.name(), case.scope(), case.calls(), case.rows()),
                (name, scope, calls, rows)
            );
        }
        for name in [
            "",
            "tool-setup",
            "installed-cli-local-check",
            "git-index-cli-native",
            "git-upstream-local",
        ] {
            assert_eq!(Case::parse(name), None);
        }
        for role in [
            None,
            Some("ordinary-image"),
            Some("installed-shell-observation"),
        ] {
            for scope in [
                None,
                Some("tool-setup"),
                Some("git-fetch-native"),
                Some("git-native"),
            ] {
                for arm in [false, true] {
                    assert_eq!(
                        selected(role, scope, arm),
                        arm && role == Some("installed-shell-observation")
                            && scope == Some("git-native")
                    );
                }
            }
        }
        let revision = "a".repeat(64);
        let references = "b".repeat(64);
        assert_eq!(
            serde_json::to_value(fixed_action(Case::Index, &revision, &references)).unwrap(),
            json!({"kind":"stage","expectedRevision":revision,"paths":["untracked.txt"]})
        );
        assert_eq!(
            serde_json::to_value(fixed_action(Case::Branch, &revision, &references)).unwrap(),
            json!({"kind":"branch-create","expectedRevision":revision,"expectedReferenceRevision":references,"name":"observer-local"})
        );
        assert_eq!(
            (SECONDS, local::WORK_SECONDS, local::HARD_SECONDS),
            (120, 45, 55)
        );
        // Actual outer-shape DATA only. No GitCli fixture, Control, final
        // report or capture is fabricated; exclusion alone cannot settle.
        let fact = super::super::FileFact {
            identity: [0; 9],
            sha256: "a".repeat(64),
        };
        let mut f = super::super::Fixture {
            root: "/inert-git-cli-shape".into(),
            uid: 501,
            root_identity: [0; 6],
            app_identity: Some([1; 6]),
            untouched: None,
            ignore: fact.clone(),
            config: Some(fact.clone()),
            release: Some([2; 6]),
            ios: None,
            project_fields: None,
            recovery: None,
            local_edits: None,
            checks: None,
            identity: None,
            tools: None,
            git_fetch: None,
            git_push: None,
            git_upstream: None,
            git_cli: None,
            written: false,
            mutated: false,
        };
        assert!(FinalReadback::fixture_shape(&f));
        f.written = true;
        assert!(!FinalReadback::fixture_shape(&f));
        f.written = false;
        f.mutated = true;
        assert!(!FinalReadback::fixture_shape(&f));
        f.mutated = false;
        f.untouched = Some([fact.clone(), fact.clone(), fact]);
        assert!(!FinalReadback::fixture_shape(&f));
    }

    fn observed(case: Case, after: bool) -> read::Projection {
        read::Projection {
            operation_id: "git-read-1".into(),
            context: read::Context {
                project_id: "fixture".into(),
                generation: 1,
                revision: "a".repeat(64),
            },
            action: read::Action {
                kind: read::Kind::Observe,
                expected_revision: None,
                paths: Vec::new(),
                staged: false,
            },
            phase: read::Phase::Settled,
            outcome: Some(read::Outcome::Ok),
            reason: None,
            result: json!({"basis":"local-refs-no-fetch","referenceRevision":"b".repeat(64),
                "tracking":{"state":"not-configured","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null},
                "observation":{"revision":"a".repeat(64),"head":"c".repeat(40),"branch":"refs/heads/main","unborn":false,"detached":false,
                    "changes":[{"path":"untracked.txt","index":if case==Case::Index&&after{"A"}else{"?"},
                        "worktree":if case==Case::Index&&after{" "}else{"?"},"kind":"file","conflict":false}],
                    "restrictions":[],"remotes":[]}}),
        }
    }
    #[test]
    fn git_cli_readback_compares_original_context_and_exact_delta_not_ready_data() {
        let accepts = |p: &read::Projection, head: &str, case, after| read_result(p, head, case, after, &mut None).is_ok();
        for case in [Case::Index, Case::Branch] {
            for after in [false, true] {
                let p = observed(case, after);
                let original = ReadOriginal::capture(&p);
                assert!(accepts(&p, &"c".repeat(40), case, after) && original.matches(&p));
                let mut other = p.clone();
                other.operation_id = "git-read-2".into();
                assert!(!original.matches(&other));
                other = p.clone();
                other.context.generation += 1;
                assert!(!original.matches(&other));
                other = p.clone();
                other.action.staged = true;
                assert!(!original.matches(&other));
                other = p.clone();
                other.phase = read::Phase::Running;
                assert!(!accepts(&other, &"c".repeat(40), case, after));
                other = p.clone();
                other.reason = Some("cancelled".into());
                assert!(!accepts(&other, &"c".repeat(40), case, after));
                other = p.clone();
                other.result["observation"]["head"] = json!("d".repeat(40));
                assert!(!accepts(&other, &"c".repeat(40), case, after));
                other = p.clone();
                other.result["observation"]["changes"] = json!([]);
                assert!(!accepts(&other, &"c".repeat(40), case, after));
                other = p.clone();
                other.result["observation"]["remotes"] = json!(["origin"]);
                assert!(!accepts(&other, &"c".repeat(40), case, after));
                other = p.clone();
                other.result["tracking"]["state"] = json!("gone");
                assert!(!accepts(&other, &"c".repeat(40), case, after));
            }
        }
        assert!(!accepts(
            &observed(Case::Index, true),
            &"c".repeat(40),
            Case::Branch,
            true
        ));
    }

    #[test]
    fn git_cli_failed_read_retains_only_the_validation_actually_reached() {
        let head = "c".repeat(40);
        let mut p = observed(Case::Index, false);
        for phase in [read::Phase::Starting, read::Phase::Running, read::Phase::Stopping, read::Phase::CleanupUnknown] {
            p.phase = phase;
            let mut valid = None;
            assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Err(ReadCheck::TerminalPhase));
            assert_eq!(valid, None);
        }
        p.phase = read::Phase::Settled;
        for outcome in [None, Some(read::Outcome::Refused), Some(read::Outcome::Cancelled), Some(read::Outcome::TimedOut), Some(read::Outcome::CleanupUnknown)] {
            p.outcome = outcome;
            let mut valid = None;
            assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Err(ReadCheck::TerminalOutcome));
            assert_eq!(valid, None);
        }
        p.outcome = Some(read::Outcome::Ok);
        p.reason = Some("command-failed".into());
        let mut valid = None;
        assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Err(ReadCheck::TerminalReason));
        assert_eq!(valid, None);
        p.reason = None;
        p.result["observation"]["head"] = json!("invalid-oid");
        assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Err(ReadCheck::ResultSchema));
        assert_eq!(valid, Some(false));
        p.result["observation"]["head"] = json!("d".repeat(40));
        assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Err(ReadCheck::FixtureComparison));
        assert_eq!(valid, Some(true));
        p.result["observation"]["head"] = json!(head);
        assert_eq!(read_result(&p, &head, Case::Index, false, &mut valid), Ok(()));
        assert_eq!(valid, Some(true));
    }

    #[test]
    fn git_cli_fixed_phase_projection_and_comparison_debt_stay_bounded() {
        // DATA only: no Fixture, FD, grant, native job or private receipt exists.
        let origin = json!({"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
        let native = [
            json!({"phase":"allowed","projectId":"1".repeat(32),"grantId":"4".repeat(32),
                "repositoryRevision":"a".repeat(64),"referenceRevision":"b".repeat(64),"selectionSha256":"c".repeat(64)}),
            json!({"phase":"prepared","prepareOperationId":"x".repeat(96),"reviewId":"y".repeat(96),"reviewDigest":"a".repeat(64),"statusSha256":"b".repeat(64)}),
            json!({"phase":"terminal","applyOperationId":"z".repeat(96),"statusSha256":"c".repeat(64)}),
            json!({"phase":"revoked"}),
            json!({"phase":"reallowed"}),
        ];
        let driver = [
            json!({"phase":"submitted","origin":origin}),
            json!({"phase":"started","origin":origin,"prepareOperationId":"x".repeat(96),"reviewId":"y".repeat(96)}),
            json!({"phase":"checked","origin":origin,"statusSha256":"c".repeat(64)}),
            json!({"phase":"denied"}),
            json!({"phase":"done","origin":origin,"statusSha256":"c".repeat(64)}),
        ];
        for rows in [&native, &driver] {
            let mut total = 0;
            for row in rows {
                let bytes = crate::edit_protocol::bounded(row, 512).unwrap();
                total += bytes.len() + 1;
            }
            assert!(total <= 4096);
        }
        assert_eq!(
            COMPARISON_BACKING,
            read::RESULT_BACKING + local::REVIEW_BACKING + 1024 * 1024
        );
        // Fixed temporary metadata fits the separate comparison slack. This is
        // NOT a whole-Document/ABI fit or a native execution claim.
        assert!(
            std::mem::size_of::<Record>()
                + std::mem::size_of::<Control>()
                + 4 * std::mem::size_of::<Fixture>()
                + 4 * 65536
                + 32 * 512
                < 1024 * 1024
        );
        let config=b"[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n[user]\nname = MRK Upstream Fixture\nemail = upstream-fixture@example.invalid\n";
        assert!(fixture::fixture_config(config));
        for extra in [
            b"[remote \"origin\"]\nurl=https://example.invalid/x\n".as_slice(),
            b"hooksPath=/tmp/hooks\n",
            b"[user]\n",
        ] {
            let mut other = config.to_vec();
            other.extend_from_slice(extra);
            assert!(!fixture::fixture_config(&other));
        }
    }
}
