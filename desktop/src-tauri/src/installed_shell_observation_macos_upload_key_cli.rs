//! One fixed extension of the existing upload-key Control and installed CLI
//! caller. The recipe never executes a command, makes a native receipt or
//! supplies a picker path to the credential owner.
use super::super::super::{cli as caller, OpenHistory, Record as OuterRecord, Step as OuterStep};
use super::*;
use crate::asset_session::CredentialBackupChoice as Choice;
use crate::{
    asset_session::{GuiCall, OriginalWork},
    service_protocol::{Id, Settlement},
    service_upload_key_protocol as p,
};
use mrk_macos_installed_native::PanelKind;
pub(crate) const SCOPE: &str = "upload-key-backup-cli";
// Additional comparison-only case backing. The existing tool-image census
// still independently charges caller::BACKING (two4KiB phase files/parse,
// <=16 original FDs and one native snapshot). Keep that old debit unchanged.
// This adds the actual case/control/trace cells, three bounded public views
// with typed+Value+encoded overlap, six distinct retained OriginalWork weak
// bodies (generation/export/import/load/bind/cancel), five GuiCall/OpenRelease
// histories, and at most ten4KiB path buffers (Control2 + Flow5 + pair2 + one clone).
// Material/source/private native buffers retain their ordinary census too.
const ARC_BYTES: usize = 2 * std::mem::size_of::<usize>();
pub(crate) const BACKING: usize = 3 * p::VIEW_LIMIT * 4
    + std::mem::size_of::<Record>()
    + std::mem::size_of::<Control>()
    + ARC_BYTES
    + std::mem::size_of::<Flow>()
    + std::mem::size_of::<super::backup::Flow>()
    + std::mem::size_of::<crate::asset_source::ComponentPair>()
    + 6 * (std::mem::size_of::<OriginalWork>() + ARC_BYTES)
    + 5 * (std::mem::size_of::<GuiCall>()
        + std::mem::size_of::<super::super::super::OpenRelease>()
        + 2 * ARC_BYTES)
    + 10 * crate::asset_source::PATH_LIMIT;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Export,
    Restore,
    CancelRestore,
}
impl Phase {
    pub(crate) fn serial(self) -> u8 {
        match self {
            Self::Export => 1,
            Self::Restore => 7,
            Self::CancelRestore => 10,
        }
    }
    pub(crate) fn original(self) -> u32 {
        match self {
            Self::Export => 6,
            Self::Restore => 10,
            Self::CancelRestore => 13,
        }
    }
    pub(crate) fn kind(self) -> p::Kind {
        if self == Self::Export {
            p::Kind::BackupEncrypted
        } else {
            p::Kind::RestoreEncrypted
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Export => 0,
            Self::Restore => 1,
            Self::CancelRestore => 2,
        }
    }
    fn allowed(self) -> &'static str {
        match self {
            Self::Export => "export-allowed",
            Self::Restore => "restore-allowed",
            Self::CancelRestore => "cancel-allowed",
        }
    }
    fn submitted(self) -> &'static str {
        match self {
            Self::Export => "export-submitted",
            Self::Restore => "restore-submitted",
            Self::CancelRestore => "cancel-submitted",
        }
    }
    fn terminal(self) -> &'static str {
        match self {
            Self::Export => "export-terminal",
            Self::Restore => "restore-terminal",
            Self::CancelRestore => "cancelled-terminal",
        }
    }
}
#[derive(Default)]
pub(crate) struct Flow {
    folders: OnceLock<[PathBuf; 2]>,
    targets: OnceLock<[PathBuf; 2]>,
    application: OnceLock<PathBuf>,
    pub(crate) cancel_owner: OnceLock<Weak<OriginalWork>>,
    pub(crate) no_io: AtomicBool,
    bound: AtomicBool,
    finished: AtomicBool,
}
impl Flow {
    pub(crate) fn application(&self) -> Option<&Path> {
        self.application.get().map(PathBuf::as_path)
    }
    fn remember_folders(&self, paths: [PathBuf; 2]) -> Result<(), ()> {
        if paths[0] == paths[1]
            || paths
                .iter()
                .any(|p| p.capacity() > crate::asset_source::PATH_LIMIT)
        {
            return Err(());
        }
        self.folders.set(paths).map_err(|_| ())
    }
    pub(crate) fn remember_targets(
        &self,
        paths: [PathBuf; 2],
    ) -> Result<(), crate::asset_commands::Reason> {
        use crate::asset_commands::Reason;
        if paths[0] == paths[1] || paths.iter().any(|p| p.capacity() > 4096) {
            return Err(Reason::Capacity);
        }
        self.targets.set(paths).map_err(|_| Reason::SourceChanged)
    }
    pub(crate) fn bound_returned(&self) -> bool {
        self.bound.load(Ordering::SeqCst)
    }
    pub(super) fn finished(&self, originals: usize) -> bool {
        originals == 13 && self.finished.load(Ordering::SeqCst)
    }
    pub(in super::super::super) fn target(&self, id: u32, kind: PanelKind) -> Option<&Path> {
        let i = panel_index(id, kind)?;
        match i {
            0 | 1 => self.folders.get()?.get(i as usize).map(PathBuf::as_path),
            2 | 3 => self
                .targets
                .get()?
                .get((i - 2) as usize)
                .map(PathBuf::as_path),
            4 => self.targets.get()?.first().map(PathBuf::as_path),
            _ => None,
        }
    }
}
pub(in super::super::super) fn selected(case: super::super::super::Case) -> bool {
    case == super::super::super::Case::Vault(super::super::Case::UploadKey(Case::BackupCli))
}
pub(in super::super::super) fn panel(i: u8) -> Option<(u32, PanelKind, Choice)> {
    Some(match i {
        0 => (
            6,
            PanelKind::EncryptedDestination,
            Choice::EncryptedDestination,
        ),
        1 => (
            6,
            PanelKind::RecoveryDestination,
            Choice::RecoveryDestination,
        ),
        2 => (10, PanelKind::EncryptedBackup, Choice::EncryptedBackup),
        3 => (10, PanelKind::RecoveryCode, Choice::RecoveryCode),
        4 => (13, PanelKind::EncryptedBackup, Choice::EncryptedBackup),
        _ => return None,
    })
}
pub(in super::super::super) fn panel_index(id: u32, kind: PanelKind) -> Option<u8> {
    (0..5).find(|i| panel(*i).is_some_and(|(n, k, _)| n == id && k == kind))
}
fn outer(s: Step) -> OuterStep {
    OuterStep::UploadKey(super::Step::BackupCli(s))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super::super) enum Step {
    Allow(Phase),
    Submitted(Phase),
    Native(u8),
    Chosen(u8),
    Terminal(Phase),
    Checked(Phase),
    LockSource,
    SourceLocked,
    Open,
    Opened,
    Prepare,
    Prepared,
    Initialize,
    Initialized,
    Context,
    Load,
    Loaded,
    Bind,
    Bound,
    Second,
    CancelRequested,
    LockTarget,
    TargetLocked,
}
struct Pick {
    original: Weak<OriginalWork>,
    call: Weak<GuiCall>,
    choice: Choice,
    history: OpenHistory,
}
pub(in super::super::super) struct Record {
    files: caller::fixture::Files,
    grants: [Option<p::Access>; 3],
    requests: [Option<Id>; 3],
    digests: [Option<String>; 3],
    pub(in super::super::super) attached: [bool; 5],
    pub(in super::super::super) actions: [bool; 5],
    picks: [Option<Pick>; 5],
    source_locked: bool,
    initialized: bool,
    bound: bool,
    done: bool,
    host: Option<usize>,
}
impl Record {
    pub(in super::super::super) fn new(
        project: &Path,
        uid: u32,
        control: &Control,
    ) -> Result<Self, ()> {
        if !caller::admitted() {
            return Err(());
        }
        if control.case != super::super::Case::UploadKey(Case::BackupCli)
            || control.root.capacity() > crate::asset_source::PATH_LIMIT
            || control.project.capacity() > crate::asset_source::PATH_LIMIT
        {
            return Err(());
        }
        let files = caller::fixture::Files::capture_backup(project, uid)?;
        let application = files.application()?;
        if application.capacity() > 4096 || control.upload.cli.application.set(application).is_err()
        {
            return Err(());
        }
        Ok(Self {
            files,
            grants: std::array::from_fn(|_| None),
            requests: std::array::from_fn(|_| None),
            digests: std::array::from_fn(|_| None),
            attached: [false; 5],
            actions: [false; 5],
            picks: std::array::from_fn(|_| None),
            source_locked: false,
            initialized: false,
            bound: false,
            done: false,
            host: None,
        })
    }
}
fn row(r: &mut OuterRecord) -> Result<&mut Record, BridgeError> {
    r.vault_record
        .as_mut()
        .and_then(|v| v.upload.cli.as_mut())
        .ok_or_else(BridgeError::invalid)
}
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|n| o.contains_key(*n)))
}
fn terminal(s: &p::Status, phase: Phase, permission: &p::Access, request: &Id) -> bool {
    s.validate().is_ok()
        && s.origin.request_id == *request
        && Some(&s.origin.project_id) == permission.project_id.as_ref()
        && Some(&s.origin.service_instance) == permission.service_instance.as_ref()
        && Some(&s.grant_id) == permission.grant_id.as_ref()
        && s.kind == phase.kind()
        && s.asset_operation_id == Some(phase.original())
        && s.settlement == Settlement::Settled
        && s.state
            == match phase {
                Phase::Export => p::State::BackupDelivered,
                Phase::Restore => p::State::RestoredUnassigned,
                Phase::CancelRestore => p::State::Cancelled,
            }
        && s.reason
            == if phase == Phase::CancelRestore {
                p::Reason::PermissionRevoked
            } else {
                p::Reason::None
            }
}
impl Observation {
    /// Called after THIS GuiCall's real loop, close, release and Open worker
    /// returns, before the same coordinator enters its second chooser.
    pub(crate) fn backup_cli_picker_returned(
        &self,
        owner: &Arc<OriginalWork>,
        call: &Arc<GuiCall>,
        choice: Choice,
    ) -> Result<(), ()> {
        if !selected(self.case) || !self.timely() {
            return Err(());
        }
        let i = (0..5)
            .find(|i| panel(*i).is_some_and(|(id, _, c)| id == owner.id && c == choice))
            .ok_or(())? as usize;
        let witness = call.installed_native_response()?.ok_or(())?;
        let (_, kind, _) = panel(i as u8).ok_or(())?;
        let target = self.open_identity_target(owner.id, kind).ok_or(())?;
        if witness.operation_id != owner.id
            || !witness.callback_returned
            || witness.response != crate::asset_session::NativeResponse::Accept
            || witness.selected.as_deref() != Some(target)
        {
            return Err(());
        }
        let mut r = self.record().ok_or(())?;
        if r.step != outer(Step::Chosen(i as u8))
            || r.pending.is_some()
            || r.prepared_open.is_some()
        {
            return Err(());
        }
        let (Some(sample), Some(identity), Some(completion), Some(progress)) = (
            r.open_sample(),
            r.identity_binding,
            r.completion_selection,
            r.open_progress.clone(),
        ) else {
            return Err(());
        };
        if !sample.succeeded()
            || sample.id != owner.id
            || !identity.input_bound(owner.id)
            || !completion.succeeded(owner.id)
            || progress.snapshot().state != "retired"
        {
            return Err(());
        }
        let c = row(&mut r).map_err(|_| ())?;
        if c.picks[i].is_some()
            || !c.actions[i]
            || c.picks
                .iter()
                .flatten()
                .any(|p| p.call.as_ptr() == Arc::as_ptr(call))
        {
            return Err(());
        }
        c.picks[i] = Some(Pick {
            original: Arc::downgrade(owner),
            call: Arc::downgrade(call),
            choice,
            history: OpenHistory {
                sample,
                identity,
                completion,
                progress,
            },
        });
        r.accessibility = None;
        r.identity_binding = None;
        r.completion_selection = None;
        r.open_progress = None;
        r.step = outer(match i {
            0 => Step::Native(1),
            1 => Step::Terminal(Phase::Export),
            2 => Step::Native(3),
            3 => Step::Terminal(Phase::Restore),
            4 => Step::Second,
            _ => return Err(()),
        });
        Ok(())
    }
    pub(in super::super::super) async fn backup_cli_tick(
        self: &Arc<Self>,
        document: &DocumentBinding,
        step: Step,
    ) {
        let result: Result<Option<Step>, BridgeError> = async {
            let bad=BridgeError::invalid;let asset=|_:crate::asset_commands::AssetError|bad();
            if !selected(self.case) || !caller::admitted(){return Err(bad());}
            let control=self.vault.as_ref().ok_or_else(bad)?;
            let project=self.record().and_then(|r|r.project.as_ref().map(|p|p.id.clone())).ok_or_else(bad)?;
            Ok(match step {
                Step::Allow(phase)=>{
                    if phase==Phase::Export {
                        let path={let mut r=self.record().ok_or_else(bad)?;
                            if !r.retain_open(1){return Err(bad());}
                            row(&mut r)?.files.application().map_err(|_|bad())?};
                        if control.upload.cli.application()!=Some(path.as_path()){return Err(bad());}
                        let checked=document.application_read_status()?;
                        let read=document.allow_application_read(&project,checked.permission_revision,&path).await?;
                        if !read.enabled || read.remaining_ms==0 || read.project_ids.len()!=1{return Err(bad());}
                        let parent=control.root().parent().ok_or_else(bad)?;
                        control.upload.cli.remember_folders([parent.join("backup"),parent.join("recovery")]).map_err(|_|bad())?;
                    }
                    let access=document.installed_backup_cli_allow(&project,phase)?;
                    if access.validate().is_err() || !access.enabled || access.consumed || access.request_id.is_some()
                        || access.kind!=Some(phase.kind()) {return Err(bad());}
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;let index=phase.index();
                    if c.grants[index].is_some() || c.grants.iter().flatten().any(|g|g.grant_id==access.grant_id) {return Err(bad());}
                    c.files.send(&json!({"phase":phase.allowed(),"projectId":access.project_id,"serviceInstance":access.service_instance,"grantId":access.grant_id})).map_err(|_|bad())?;
                    c.grants[index]=Some(access);Some(Step::Submitted(phase))
                }
                Step::Submitted(phase)=>{
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;let i=phase.index();
                    if let Some(v)=c.files.poll(i*2,phase.submitted()).map_err(|_|bad())? {
                        if !keys(&v,&["phase","requestId"]) || c.requests[i].is_some() {return Err(bad());}
                        let id=Id::parse(v["requestId"].as_str().ok_or_else(bad)?).map_err(|_|bad())?;
                        if c.requests.iter().flatten().any(|old|*old==id){return Err(bad());}
                        c.requests[i]=Some(id);Some(Step::Native((i*2) as u8))
                    }else{None}
                }
                Step::Terminal(phase)=>{
                    let Some(status)=document.installed_backup_cli_status(phase).map_err(asset)? else{return Ok(None);};
                    if status.settlement==Settlement::Pending{return Ok(None);}
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;let i=phase.index();
                    if !terminal(&status,phase,c.grants[i].as_ref().ok_or_else(bad)?,c.requests[i].as_ref().ok_or_else(bad)?) {return Err(bad());}
                    // The positive helpers additionally compare native publication/private drain.
                    drop(r);
                    if phase==Phase::Export && document.installed_generated_backup_exported()!=Some(true)
                        || phase==Phase::Restore && document.installed_generated_backup_imported()!=Some(true)
                        || phase==Phase::CancelRestore && !control.upload.cli.no_io.load(Ordering::SeqCst){return Err(bad());}
                    let mut value=serde_json::to_value(&status).map_err(|_|bad())?;value.sort_all_objects();
                    let bytes=crate::edit_protocol::bounded(&value,p::VIEW_LIMIT)?;
                    let hash=super::super::super::digest(&bytes);
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;
                    c.files.send(&json!({"phase":phase.terminal(),"requestId":status.origin.request_id,
                        "assetOperationId":status.asset_operation_id,"statusSha256":hash})).map_err(|_|bad())?;
                    c.digests[i]=Some(hash);Some(Step::Checked(phase))
                }
                Step::Checked(phase)=>{
                    let i=phase.index();let (name,index)=match phase{Phase::Export=>("export-checked",1),Phase::Restore=>("restore-checked",3),Phase::CancelRestore=>("done",6)};
                    let grant={let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;
                        let Some(v)=c.files.poll(index,name).map_err(|_|bad())? else{return Ok(None);};
                        if !keys(&v,&["phase","requestId","statusSha256"]) || v["requestId"].as_str()!=c.requests[i].as_ref().map(Id::as_str)
                            || v["statusSha256"].as_str()!=c.digests[i].as_deref(){return Err(bad());}
                        c.grants[i].as_ref().and_then(|g|g.grant_id.clone()).ok_or_else(bad)?};
                    let revoke=crate::asset_session::agent_upload_key::decode_revoke(&crate::edit_protocol::bounded(&json!({"consentId":grant}),128)?)?;
                    let access=document.revoke_agent_upload_key("main",revoke)?;
                    if access.enabled || access.grant_id.as_ref()!=Some(&grant) || !access.consumed{return Err(bad());}
                    Some(match phase{Phase::Export=>Step::LockSource,Phase::Restore=>Step::Load,Phase::CancelRestore=>Step::LockTarget})
                }
                Step::LockSource=>{document.installed_generated_backup_lock_source().map_err(asset)?;Some(Step::SourceLocked)}
                Step::Open=>{document.installed_generated_backup_open().map_err(asset)?;Some(Step::Opened)}
                Step::Prepare=>{document.installed_generated_backup_prepare().map_err(asset)?;Some(Step::Prepared)}
                Step::Initialize=>{document.installed_generated_backup_initialize().map_err(asset)?;Some(Step::Initialized)}
                Step::Context=>{document.installed_generated_backup_context(&self.base,&project).map_err(asset)?;Some(Step::Allow(Phase::Restore))}
                Step::Load=>{document.installed_generated_backup_load().map_err(asset)?;Some(Step::Loaded)}
                Step::Loaded=>match document.installed_generated_backup_loaded(){Some(true)=>Some(Step::Bind),Some(false)=>return Err(bad()),None=>None},
                Step::Bind=>{document.installed_generated_backup_bind().map_err(asset)?;Some(Step::Bound)}
                Step::Bound=>match document.installed_generated_backup_bound(){Some(true)=>{
                    let mut r=self.record().ok_or_else(bad)?;row(&mut r)?.bound=true;
                    if control.upload.cli.bound.swap(true,Ordering::SeqCst){return Err(bad());}
                    Some(Step::Allow(Phase::CancelRestore))},Some(false)=>return Err(bad()),None=>None},
                Step::Second=>{
                    if !document.installed_backup_cli_second_entered().map_err(asset)?{return Ok(None);}
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;
                    c.files.send(&json!({"phase":"second-entered","requestId":c.requests[2],"assetOperationId":13})).map_err(|_|bad())?;
                    Some(Step::CancelRequested)
                }
                Step::CancelRequested=>{
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;
                    if let Some(v)=c.files.poll(5,"cancel-requested").map_err(|_|bad())?{
                        if !keys(&v,&["phase","requestId"]) || v["requestId"].as_str()!=c.requests[2].as_ref().map(Id::as_str){return Err(bad());}
                        Some(Step::Terminal(Phase::CancelRestore))
                    }else{None}
                }
                Step::LockTarget=>{document.installed_backup_cli_lock_target().map_err(asset)?;Some(Step::TargetLocked)}
                Step::SourceLocked|Step::Opened|Step::Prepared|Step::Initialized|Step::TargetLocked=>{
                    let Some(s)=document.installed_macos_vault_snapshot()else{return Ok(None);};
                    if s.unknown{return Err(bad());}if !s.originals_settled{return Ok(None);}
                    let mut r=self.record().ok_or_else(bad)?;let c=row(&mut r)?;
                    match step {
                        Step::SourceLocked if s.originals==6 && s.empty=>{c.source_locked=true;Some(Step::Open)}
                        Step::Opened if s.originals==7 && s.state==Some("uninitialized") && !s.key_present=>Some(Step::Prepare),
                        Step::Prepared if s.originals==8 && s.initialize_preview=>Some(Step::Initialize),
                        Step::Initialized if s.originals==9 && s.state==Some("unlocked") && s.key_present && s.preview_consumed
                            && s.initialize.as_ref().is_some_and(|h|h.successful_consumption())
                            && s.storage.is_some_and(|s|s.reservation_durable() && s.header_durable())=>{c.initialized=true;Some(Step::Context)}
                        Step::TargetLocked if s.originals==13 && s.empty=>{
                            if !c.source_locked || !c.initialized || !c.bound || c.picks.iter().any(Option::is_none)
                                || !control.upload.cli.no_io.load(Ordering::SeqCst){return Err(bad());}
                            c.files.finish_backup().map_err(|_|bad())?;c.done=true;
                            control.upload.cli.finished.store(true,Ordering::SeqCst);
                            if !control.finish(13) || r.fixture.verify(true).is_err(){return Err(bad());}
                            r.vault_record.as_mut().ok_or_else(bad)?.original_count=13;r.file_readback=true;r.step=OuterStep::Close;
                            return Ok(None);
                        }
                        _=>return Err(bad()),
                    }
                }
                Step::Native(_)|Step::Chosen(_)=>return Ok(None),
            })
        }.await;
        match result {
            Ok(Some(next)) => {
                if !self.timely() {
                    return;
                }
                let Some(mut r) = self.record() else {
                    return;
                };
                if r.step != outer(step) {
                    self.fail_with("upload-key-original-contract");
                    return;
                }
                r.step = outer(next);
            }
            Ok(None) => {}
            Err(_) => self.fail_with("upload-key-original-contract"),
        }
    }
    pub(crate) fn backup_cli_host_return(
        &self,
        report: &crate::application_service_host::HostShutdownReport,
    ) -> bool {
        let Some(mut r) = self.record() else {
            return false;
        };
        let Ok(c) = row(&mut r) else {
            return false;
        };
        if !selected(self.case)
            || !c.done
            || !c.files.closed()
            || c.host.is_some()
            || !report.settled()
            || !report.failures.is_empty()
            || report.workers_joined != Some(10)
        {
            self.fail_with("installed-cli-original-contract");
            return false;
        }
        c.host = report.workers_joined;
        true
    }
}
pub(super) fn report(r: &super::super::Record, control: &Control) -> Option<Value> {
    let c = r.upload.cli.as_ref()?;
    if control.case != super::super::Case::UploadKey(Case::BackupCli)
        || !control.completed()
        || !r.final_originals
        || r.original_count != 13
        || !r.upload.repeated_refused
        || !r.upload.sample.is_some_and(|s| s.positive())
        || !c.done
        || !c.files.closed()
        || c.host != Some(10)
        || !c.bound
        || !c.initialized
        || !c.source_locked
        || !control.upload.cli.no_io.load(Ordering::SeqCst)
        || c.actions != [true; 5]
        || c.picks.iter().any(|p| {
            p.as_ref().is_none_or(|p| {
                !p.history.sample.succeeded()
                    || p.history.progress.snapshot().state != "retired"
                    || p.original.as_ptr().is_null()
                    || p.call.as_ptr().is_null()
            })
        })
    {
        return None;
    }
    Some(
        json!({"schemaVersion":1,"scope":SCOPE,"requests":c.requests,"statusSha256":c.digests,
        "originalCount":14,"openActions":5,"pickerCalls":6,"cancelledBeforeIo":true,"explicitBind":true,
        "allOriginalsSettled":true,"hostWorkersJoined":10,"sourceLockedBeforeRestore":true,
        "shippingEnabled":false,"rendererInteractionTested":false,"restartTested":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(case: Case) -> Arc<Control> {
        // Original selector DATA only, deliberately no registered Document,
        // Observation, Host or native participant. Cannot consume admission.
        Arc::new(Control {
            case: super::super::super::Case::UploadKey(case),
            root: "/Users/inert/vault".into(),
            project: "/private/tmp/inert-project".into(),
            original: OnceLock::new(),
            document: OnceLock::new(),
            claimed: AtomicBool::new(false),
            returned: AtomicBool::new(false),
            next: AtomicU8::new(3),
            checkpoint: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            quit: AtomicU8::new(9),
            upload: super::super::Flow::default(),
        })
    }

    #[test]
    fn prepare_uses_same_captured_application_not_vault_root_and_never_rereserves() {
        let c = control(Case::BackupCli);
        let d = Arc::new(());
        let other = Arc::new(());
        let app = PathBuf::from(
            "/Users/inert/.c-original/Library/Application Support/dev.mobile-release-kit.desktop",
        );
        c.upload.cli.application.set(app.clone()).unwrap();
        assert!(c
            .upload
            .cli
            .application
            .set("/Users/inert/replacement".into())
            .is_err());
        c.upload.next.store(6, Ordering::SeqCst);
        let selection = super::super::Selection {
            control: c.clone(),
            document: Arc::downgrade(&d),
            action: super::super::Action::Prepare,
            serial: 6,
            spent: AtomicBool::new(false),
        };
        assert!(!selection.claim(&d, 4, Some(c.root())));
        assert!(!selection.claim(&other, 4, Some(&app)));
        assert!(!selection.claim(&d, 5, Some(&app)));
        assert!(selection.claim(&d, 4, Some(&app)));
        assert!(!selection.claim(&d, 4, Some(&app)));
        assert!(selection.consume(&d, 4, Some(&app)).is_none());
        assert!(!c.permits(&d)); // DATA path equality does not admit an observer.
        let b = control(Case::BackupRoundTrip);
        b.upload.next.store(6, Ordering::SeqCst);
        let old = super::super::Selection {
            control: b.clone(),
            document: Arc::downgrade(&d),
            action: super::super::Action::Prepare,
            serial: 6,
            spent: AtomicBool::new(false),
        };
        assert!(!old.claim(&d, 4, Some(&app)));
        assert!(old.claim(&d, 4, Some(b.root()))); // Existing B unchanged.
    }

    #[test]
    fn only_five_exact_choice_opens_and_cancel_second_has_no_open_target() {
        let f = Flow::default();
        f.remember_folders(["/private/inert/backup".into(), "/private/inert/code".into()])
            .unwrap();
        f.remember_targets([
            "/private/inert/backup/a.mrkbackup".into(),
            "/private/inert/code/a.mrkcode".into(),
        ])
        .unwrap();
        assert!(f
            .remember_targets(["/other/a".into(), "/other/b".into()])
            .is_err());
        for i in 0..5 {
            let (id, kind, _) = panel(i).unwrap();
            assert_eq!(panel_index(id, kind), Some(i));
            assert!(f.target(id, kind).is_some());
        }
        assert!(panel(5).is_none());
        assert!(f.target(13, PanelKind::RecoveryCode).is_none());
        assert!(f.target(6, PanelKind::RecoveryCode).is_none());
        assert!(f.target(10, PanelKind::EncryptedDestination).is_none());
        assert!(!f.finished(13));
        for (p, id, serial) in [
            (Phase::Export, 6, 1),
            (Phase::Restore, 10, 7),
            (Phase::CancelRestore, 13, 10),
        ] {
            assert_eq!((p.original(), p.serial()), (id, serial));
        }
    }

    #[test]
    fn actual_validated_terminal_requires_same_grant_original_and_known_effect() {
        let id = |n: u8| Id::parse(&format!("{n:032x}")).unwrap();
        let access = p::Access {
            schema_version: 1,
            service_instance: Some(id(1)),
            project_id: Some(id(2)),
            grant_id: Some(id(3)),
            kind: Some(p::Kind::BackupEncrypted),
            request_id: None,
            enabled: true,
            remaining_ms: 1000,
            consumed: false,
            prepared: None,
        };
        assert!(access.validate().is_ok());
        let s:p::Status=serde_json::from_value(json!({"schemaVersion":1,
            "origin":{"serviceInstance":id(1),"projectId":id(2),"requestId":id(4)},
            "grantId":id(3),"kind":"backup-encrypted","state":"backup-delivered","settlement":"settled",
            "reason":"none","assetOperationId":6,"key":null,"doNotReplay":true})).unwrap();
        assert!(terminal(&s, Phase::Export, &access, &id(4)));
        assert!(!terminal(&s, Phase::Restore, &access, &id(4)));
        assert!(!terminal(&s, Phase::Export, &access, &id(5)));
        for field in ["state", "settlement", "assetOperationId", "grantId"] {
            let mut v = serde_json::to_value(&s).unwrap();
            v[field] = match field {
                "state" => json!("unknown"),
                "settlement" => json!("pending"),
                "assetOperationId" => json!(10),
                _ => json!(id(8)),
            };
            let changed: p::Status = serde_json::from_value(v).unwrap();
            assert!(!terminal(&changed, Phase::Export, &access, &id(4)));
        }
    }

    #[test]
    fn additional_case_census_keeps_original_caller_and_weak_history_bodies() {
        assert_eq!(caller::BACKING, 256 * 1024); // Existing debit is separate, never replaced.
        assert!(
            BACKING
                >= std::mem::size_of::<Record>()
                    + std::mem::size_of::<Control>()
                    + 6 * std::mem::size_of::<OriginalWork>()
                    + 5 * std::mem::size_of::<GuiCall>()
                    + 10 * crate::asset_source::PATH_LIMIT
        );
        let f = Flow::default();
        let mut excessive = PathBuf::from("/inert");
        excessive.reserve(8192);
        assert!(f
            .remember_targets([excessive, "/inert/other".into()])
            .is_err());
        assert!(f.targets.get().is_none());
        let mut excessive = PathBuf::from("/inert/folder");
        excessive.reserve(8192);
        assert!(f
            .remember_folders([excessive, "/inert/other".into()])
            .is_err());
        assert!(f.folders.get().is_none());
    }
}
