//! Four direct, fixed installed ProjectIdentity observations. Not UI automation.
//! Normal RAW validation/Document/EditOwner admission and its original finality
//! remain authoritative; this leaf adds no enable flag, process or writer.
use super::*;
use crate::{project_identity_commands as commands, project_identity_edit_protocol as wire,
    edit_owner::InstalledIdentityFinality};
use std::collections::BTreeMap;

pub(super) const NAMES: [&str;4] = ["identity-android-apply", "identity-ios-apply",
    "identity-rollback-recovery", "identity-committed-cleanup"];
const OLD: &str = "com.example.reader";
const NEW: &str = "com.example.another";
const CONFIG_PATH: &str = "release/mobile-release.json";
const ANDROID_PATH: &str = "app/build.gradle.kts";
const PBX_PATH: &str = "iosApp/Reader.xcodeproj/project.pbxproj";
const SCHEME_PATH: &str = "iosApp/Reader.xcodeproj/xcshareddata/xcschemes/Reader.xcscheme";
const XCCONFIG_PATH: &str = "iosApp/Config/Release.xcconfig";
const PENDING: &str = ".mobile-release-init";
const FOREIGN: &[u8] = b"APP_ID=com.example.foreign\n";
const LATER: &[u8] = b"// Later user edit; metadata cleanup must not touch this file.\n";
const KEEP: &[u8] = b"Public unrelated source; preserve exactly.\n";

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Case { Android, Ios, Rollback, Committed }
impl Case {
    pub(super) fn name(self)->&'static str {NAMES[match self {Self::Android=>0,Self::Ios=>1,Self::Rollback=>2,Self::Committed=>3}]}
    pub(super) fn parse(name:&str)->Option<Self>{[Self::Android,Self::Ios,Self::Rollback,Self::Committed].into_iter().find(|c|c.name()==name)}
    pub(super) fn seconds(self)->u64{if self==Self::Android{150}else{105}}
    fn recovery(self)->bool{matches!(self,Self::Rollback|Self::Committed)}
    fn sessions(self)->usize{if self==Self::Android{2}else{1}}
    fn intent(self)->wire::Intent{if self.recovery(){wire::Intent::Recover}else{wire::Intent::Edit}}
    fn close(self,round:usize)->bool{self==Self::Android&&round==0}
}
pub(super) fn config(case:Case)->Vec<u8>{
    let raw=if case==Case::Ios{IOS_CONFIG}else{ANDROID_CONFIG};
    if case.recovery(){replace(raw)}else{raw.to_vec()}
}
pub(super) fn snapshot_failure(value:&Value,root:&Path,case:Case,base:&Value)->Option<&'static str>{
    let saved=&value["config"];let hints=&value["discovery"]["hints"];
    if value["root"].as_str()!=root.to_str(){return Some("snapshot-value-root");}
    if value["observationScope"]!="single-request-non-atomic"{return Some("snapshot-value-scope");}
    if !super::assurance(value,"static-text"){return Some("snapshot-value-assurance");}
    if !value["issues"].as_array().is_some_and(Vec::is_empty){return Some("snapshot-value-issues");}
    if saved["path"]!=CONFIG_PATH||saved["state"]!="format-valid"{return Some("snapshot-config-state");}
    if saved["data"]!=*base{return Some("snapshot-config-data");}
    let bytes=config(case);
    if saved["content"]!=json!({"bytes":bytes.len(),"sha256":digest(&bytes)}){return Some("snapshot-config-content");}
    if !saved["issues"].as_array().is_some_and(Vec::is_empty){return Some("snapshot-config-issues");}
    if value["discovery"]["partial"]!=false||value["discovery"]["state"]!="unverified"{return Some("snapshot-discovery-state");}
    let mut expected=json!({"versionSource":"version.properties","versionNameKey":"VERSION_NAME","versionBuildKey":"BUILD_NUMBER"});
    if case==Case::Ios{
        expected["ios"]=json!({"projects":["iosApp/Reader.xcodeproj"],"workspaces":[],"schemes":["Reader"],
            "bundleIds":[OLD],"generatedProjectSources":[],"bundleId":OLD,"project":"iosApp/Reader.xcodeproj","scheme":"Reader"});
    }else{
        expected["android"]=json!({"module":":app","buildFile":ANDROID_PATH,"applicationId":if case.recovery(){NEW}else{OLD},
            "namespace":"com.example.source","debugApplicationIdSuffix":".debug"});
    }
    if hints!=&expected{return Some("identity-original-contract");}
    None
}
fn replace(raw:&[u8])->Vec<u8>{String::from_utf8_lossy(raw).replace(OLD,NEW).into_bytes()}
fn files(case:Case,finalized:bool)->BTreeMap<String,Vec<u8>>{
    let changed=if case.recovery(){case==Case::Committed||!finalized}else{finalized};
    let mut rows=BTreeMap::from([
        (".gitignore".into(),super::Fixture::ignore_bytes(true,false)),
        (CONFIG_PATH.into(),if case==Case::Ios{IOS_CONFIG.to_vec()}else{ANDROID_CONFIG.to_vec()}),
        ("keep.txt".into(),KEEP.to_vec()),("version.properties".into(),b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n".to_vec())]);
    if case==Case::Ios {
        rows.extend([(PBX_PATH.into(),PBX.to_vec()),(SCHEME_PATH.into(),SCHEME.to_vec()),(XCCONFIG_PATH.into(),XCCONFIG.to_vec()),
            ("iosApp/Reader.swift".into(),b"// Unrelated Swift source; preserve exactly.\n".to_vec())]);
    }else{
        rows.extend([(ANDROID_PATH.into(),SOURCE.to_vec()),("settings.gradle.kts".into(),b"include(\":app\")\n".to_vec()),
            ("app/src/Unrelated.kt".into(),b"package com.example.source\n// Preserve the source package.\n".to_vec())]);
    }
    if changed {for path in if case==Case::Ios{vec![CONFIG_PATH,PBX_PATH,XCCONFIG_PATH]}else{vec![CONFIG_PATH,ANDROID_PATH]}{
        if let Some(raw)=rows.get_mut(path){*raw=replace(raw);}
    }}
    if case==Case::Committed {
        rows.insert("gradle.properties".into(),FOREIGN.to_vec());
        for path in [ANDROID_PATH,"keep.txt"]{rows.get_mut(path).unwrap().extend_from_slice(LATER);}
    }
    if case.recovery()&&!finalized {
        rows.insert(format!("{PENDING}/old-1"),SOURCE.to_vec());
        rows.insert(format!("{PENDING}/old-2"),ANDROID_CONFIG.to_vec());
    }
    rows
}
fn controls(case:Case,finalized:bool)->Vec<String>{
    if !case.recovery()||finalized{return vec![];}
    ["header.json","plan.json",if case==Case::Committed{"COMMITTED"}else{"commit.pending"},"rollback.pending"]
        .map(|name|format!("{PENDING}/{name}")).to_vec()
}
fn directories(rows:&BTreeMap<String,Vec<u8>>,controls:&[String])->Result<BTreeMap<String,Vec<String>>,()>{
    let mut result=BTreeMap::<String,Vec<String>>::from([(".".into(),vec![])]);
    for path in rows.keys().chain(controls){let parts:Vec<_>=path.split('/').collect();
        for i in 0..parts.len(){let parent=if i==0{".".into()}else{parts[..i].join("/")};
            let children=result.entry(parent).or_default();
            if !children.iter().any(|s|s==parts[i]){children.push(parts[i].to_owned());}
        }
    }
    if rows.len()>16||controls.len()>4||result.len()>16{return Err(());}
    for names in result.values_mut(){names.sort();if names.len()>16{return Err(());}}
    Ok(result)
}

// Only four compiled private-control leaves are read; their contents never
// authorize paths/actions and are never exported. Every original FD closes
// once before returning even when a read or identity check fails.
fn control_fact(path:&Path,uid:u32)->Result<FileFact,()>{
    let before=std::fs::symlink_metadata(path).map_err(|_|())?;
    let original=super::identity(&before)?;
    if !before.is_file()||before.mode()!=0o100600||before.uid()!=uid||before.nlink()!=1||before.len()==0||before.len()>65536{return Err(());}
    let mut f=OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW|nix::libc::O_CLOEXEC|nix::libc::O_NONBLOCK).open(path).map_err(|_|())?;
    let result=(||{
        if super::identity(&f.metadata().map_err(|_|())?)?!=original{return Err(());}
        mrk_macos_installed_native::empty_acl(f.as_fd()).map_err(|_|())?;
        mrk_macos_installed_native::no_xattrs(f.as_fd()).map_err(|_|())?;
        let mut bytes=Vec::new();std::io::Read::by_ref(&mut f).take(before.len()+1).read_to_end(&mut bytes).map_err(|_|())?;
        if bytes.len() as u64!=before.len()||super::identity(&f.metadata().map_err(|_|())?)?!=original
            ||super::identity(&std::fs::symlink_metadata(path).map_err(|_|())?)?!=original{return Err(());}
        Ok(FileFact{identity:original,sha256:digest(&bytes)})
    })();
    let closed=nix::unistd::close(std::os::fd::OwnedFd::from(f)).is_ok();
    if !closed{return Err(());}result
}
pub(super) struct Fixture {case:Case,finalized:bool,closed_review:bool,files:BTreeMap<String,FileFact>,dirs:BTreeMap<String,[u64;6]>}
impl Fixture {
    pub(super) fn capture(root:&Path,uid:u32,case:Case)->Result<Self,()>{
        let rows=files(case,false);let private=controls(case,false);let mut facts=BTreeMap::new();let mut dirs=BTreeMap::new();
        for (path,bytes) in &rows{facts.insert(path.clone(),file_fact(&root.join(path),bytes,uid)?);}
        for path in &private{facts.insert(path.clone(),control_fact(&root.join(path),uid)?);}
        for (path,names) in directories(&rows,&private)?{let names:Vec<_>=names.iter().map(String::as_str).collect();
            dirs.insert(path.clone(),directory(&root.join(path),uid,0o700,&names)?);}
        let value=Self{case,finalized:false,closed_review:false,files:facts,dirs};value.verify(root,uid)?;Ok(value)
    }
    pub(super) fn root_identity(&self)->Result<[u64;6],()>{self.dirs.get(".").copied().ok_or(())}
    pub(super) fn ignore(&self)->Result<FileFact,()>{self.files.get(".gitignore").cloned().ok_or(())}
    pub(super) fn file(&self,path:&str)->Option<FileFact>{self.files.get(path).cloned()}
    pub(super) fn dir(&self,path:&str)->Option<[u64;6]>{self.dirs.get(path).copied()}
    pub(super) fn verify(&self,root:&Path,uid:u32)->Result<(),()>{
        let rows=files(self.case,self.finalized);let private=controls(self.case,self.finalized);
        if self.files.len()!=rows.len()+private.len(){return Err(());}
        for (path,bytes) in &rows{if self.files.get(path)!=Some(&file_fact(&root.join(path),bytes,uid)?){return Err(());}}
        for path in &private{if self.files.get(path)!=Some(&control_fact(&root.join(path),uid)?){return Err(());}}
        let dirs=directories(&rows,&private)?;if dirs.len()!=self.dirs.len(){return Err(());}
        for (path,names) in dirs{let names:Vec<_>=names.iter().map(String::as_str).collect();
            if self.dirs.get(&path)!=Some(&directory(&root.join(path),uid,0o700,&names)?){return Err(());}}
        Ok(())
    }
    // Called only after the original EditOwner finality getter. It does not
    // invent settlement from terminal DATA or authorize rollback source reads.
    fn after(&mut self,root:&Path,uid:u32,closed:bool)->Result<(),()>{
        if self.finalized||closed&&(self.case!=Case::Android||self.closed_review){return Err(());}
        if closed{self.verify(root,uid)?;self.closed_review=true;return Ok(());}
        if self.case==Case::Android&&!self.closed_review{return Err(());}
        let before=files(self.case,false);let after=files(self.case,true);let mut facts=BTreeMap::new();let mut dirs=BTreeMap::new();
        for (path,bytes) in &after{let fact=file_fact(&root.join(path),bytes,uid)?;
            if before.get(path)==Some(bytes)&&self.files.get(path)!=Some(&fact){return Err(());}
            if self.case==Case::Rollback&&[ANDROID_PATH,CONFIG_PATH].contains(&path.as_str()){
                let backup=self.files.get(&format!("{PENDING}/old-{}",if path==ANDROID_PATH{1}else{2})).ok_or(())?;
                if fact.identity[..8]!=backup.identity[..8]||fact.sha256!=backup.sha256{return Err(());}
            }
            facts.insert(path.clone(),fact);
        }
        for (path,names) in directories(&after,&[])?{let names:Vec<_>=names.iter().map(String::as_str).collect();
            let observed=directory(&root.join(&path),uid,0o700,&names)?;
            if self.dirs.get(&path).is_none_or(|old|old[..5]!=observed[..5]){return Err(());}dirs.insert(path,observed);
        }
        self.files=facts;self.dirs=dirs;self.finalized=true;self.verify(root,uid)
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Step { Open, WaitOpen, Prepare, WaitReview, Submit, WaitFinal, Done }
struct Session {projection:wire::Projection,opened:bool,prepared:bool,reviewed:bool,submitted:bool,closed:bool,readback:bool,
    finality:Option<InstalledIdentityFinality>}
pub(super) struct Record {case:Case,generation:Option<String>,revision:u32,pending:bool,sessions:Vec<Session>}
impl Record {
    pub(super) fn new(case:Case)->Self{Self{case,generation:None,revision:0,pending:false,sessions:Vec::with_capacity(2)}}
    fn status(&mut self,status:&wire::IdentityStatus)->Result<(),()>{
        if status.schema_version!=1||status.domain!=wire::DOMAIN||!edit::token(&status.window_generation)
            ||self.generation.as_ref().is_some_and(|v|v!=&status.window_generation)||status.status_revision<self.revision
            ||!status.capability.available{return Err(());}
        self.generation=Some(status.window_generation.clone());self.revision=status.status_revision;Ok(())
    }
    pub(super) fn complete(&self)->bool{!self.pending&&self.sessions.len()==self.case.sessions()
        &&self.sessions.iter().enumerate().all(|(i,s)|s.opened&&s.prepared&&s.reviewed&&s.submitted&&s.readback
            &&s.closed==self.case.close(i)&&s.finality.as_ref().is_some_and(|f|finality(f,&s.projection,s.closed,self.case)))}
    pub(super) fn report(&self,fixture:&Fixture)->Option<Value>{
        if !self.complete()||!fixture.finalized{return None;}
        Some(json!({"scope":"original-project-identity-v1","case":self.case.name(),"identityUiAutomation":false,
            "sessions":self.sessions.iter().map(|s|json!({"sessionId":s.projection.session_id,"projectId":s.projection.project_id,
                "ownerGeneration":s.projection.owner_generation,"intent":s.projection.intent,
                "revision":s.projection.checkout.as_ref().map(|c|c.revision.as_str()),
                "planToken":s.projection.prepared.as_ref().map(|p|p.plan_token.as_str()),
                "coreOutcome":s.projection.core_outcome,"nativeReason":s.projection.native_reason,
                "nativeFinality":s.projection.native_finality,"lateSettled":s.projection.late_settled,"reviewMatched":s.reviewed,
                "originalsJoined":s.finality.as_ref().is_some_and(|f|finality(f,&s.projection,s.closed,self.case)),
                "writerFrames":s.finality.as_ref().map(|f|f.writer_frames),"stdoutFrames":s.finality.as_ref().map(|f|f.stdout_frames),
                "closedWithoutApply":s.closed,"fileReadback":s.readback})).collect::<Vec<_>>(),
            "files":fixture.files.iter().map(|(p,f)|(p.clone(),f.sha256.clone())).collect::<BTreeMap<_,_>>(),
            "controlledPrecursorRequired":self.case.recovery(),"processLossEvidence":false,"buildOrStoreVerified":false,
            "namespaceRefactor":false,"shippingBinaryQualified":false}))
    }
}
fn same(a:&wire::Projection,b:&wire::Projection)->bool{a.domain==wire::DOMAIN&&b.domain==wire::DOMAIN&&a.intent==b.intent
    &&a.project_id==b.project_id&&a.session_id==b.session_id&&a.owner_generation==b.owner_generation}
fn observed(case:Case,p:&wire::Projection)->bool{
    if p.intent!=case.intent()||p.diagnostic.is_some(){return false;}
    let Some(c)=&p.checkout else{return false;};
    if !edit::token(&c.revision){return false;}
    let v=&c.view;
    if case.recovery(){v["state"]=="recoverable"&&v["action"]==if case==Case::Committed{"committed_cleanup"}else{"rollback"}}
    else{v["state"]=="supported"&&v["identity"]==OLD&&v["identityStatus"]=="unverified"
        &&v["selection"]==json!({"platform":if case==Case::Ios{"ios"}else{"android"},"target":if case==Case::Ios{"Reader"}else{":app"},
            "project":if case==Case::Ios{Some("iosApp/Reader.xcodeproj")}else{None},"continuity":"unknown"})}
}
fn reviewed(case:Case,p:&wire::Projection)->bool{
    if !observed(case,p)||p.phase!=edit::Phase::Reviewing||p.review_remaining_ms==0||p.apply_submitted
        ||p.native_finality!=edit::NativeFinality::Pending||p.native_reason!=edit::NativeEditReason::None||p.core_outcome.is_some()||p.late_settled{return false;}
    let Some(plan)=&p.prepared else{return false;};let c=p.checkout.as_ref().unwrap();
    if plan.revision!=c.revision||!edit::token(&plan.plan_token)||plan.plan_token==c.revision{return false;}
    if case.recovery(){plan.view==c.view}else{plan.view["state"]=="change"&&plan.view["intent"]=="new-application"
        &&plan.view["warnings"]==json!(["A different identity is a different app. This cannot update your existing app. Availability in the stores has not been checked."])
        &&plan.view["changes"].as_array().is_some_and(|rows|rows.len()==if case==Case::Ios{3}else{2}
            &&rows.iter().all(|row|row["beforeId"]==OLD&&row["afterId"]==NEW))}
}
fn finality(f:&InstalledIdentityFinality,p:&wire::Projection,closed:bool,case:Case)->bool{
    p.domain==wire::DOMAIN&&p.intent==case.intent()&&p.session_id==f.session_id&&p.project_id==f.project_id&&p.owner_generation==f.owner_generation
        &&p.phase==edit::Phase::Final&&p.native_finality==edit::NativeFinality::Settled&&!p.late_settled&&p.apply_submitted!=closed
        &&p.native_reason==if closed{edit::NativeEditReason::Discarded}else{edit::NativeEditReason::None}
        &&p.core_outcome.as_ref().is_some_and(|o|o.resources==edit::ResourceState::Settled
            &&o.effect==if closed{edit::Effect::NotStarted}else if case==Case::Rollback{edit::Effect::RolledBack}else{edit::Effect::Committed}
            &&o.journal==if closed{edit::Journal::NotCreated}else{edit::Journal::Clean}
            &&o.reason==if closed{edit::CoreReason::Cancelled}else{edit::CoreReason::None})
        &&f.writer_frames==if closed{2}else{3}&&f.stdout_frames==3
        &&f.inspection_joined&&f.acquisition_joined&&f.child_waited_success&&f.stdin_closed&&f.stdout_eof_closed&&f.stderr_eof_closed
        &&f.io_joined&&f.driver_joined&&f.watchdog_joined&&f.manager_joined&&f.runtime_ledger_settled&&f.runtime_settlement_joined
}

impl Observation {
    // One synchronous original admission per relay tick. No Document/Edit lock
    // is held by this observation across a native call or file readback. Errors
    // stop the existing Observation and original shutdown joins the EditOwner.
    pub(super) fn identity_tick(self:&Arc<Self>,app:&tauri::AppHandle)->bool{
        let step=self.record().and_then(|r|if let super::Step::Identity(s)=r.step{Some(s)}else{None});
        let Some(step)=step else{return false;};
        if self.identity_advance(app,step).is_err(){self.fail_with("identity-original-contract");}
        true
    }
    fn identity_advance(&self,app:&tauri::AppHandle,step:Step)->Result<(),()>{
        use tauri::Manager;
        if !self.timely(){return Err(());}
        let state=app.try_state::<crate::shell::ShellState>().ok_or(())?;
        let webview=app.get_webview(crate::shell::MAIN_WINDOW).ok_or(())?;
        let window=webview.label();if window!=crate::shell::MAIN_WINDOW{return Err(());}
        let (case,project,round)= {let r=self.record().ok_or(())?;let record=r.identity.as_ref().ok_or(())?;
            if record.pending||!r.project_settled{return Err(());} (record.case,r.project.as_ref().ok_or(())?.id.clone(),record.sessions.len())};
        commands::status(b"{}").map_err(|_|())?;
        let status=state.bridge.edits.identity_status().map_err(|_|())?;
        let p=status.active.as_ref().or(status.last_terminal.as_ref()).cloned();
        {let mut r=self.record().ok_or(())?;r.identity.as_mut().ok_or(())?.status(&status)?;}
        let next=match step {
            Step::Open=>{
                {let mut r=self.record().ok_or(())?;let rec=r.identity.as_mut().ok_or(())?;
                    if round>=case.sessions()||status.active.is_some()||rec.sessions.iter().any(|s|!s.readback){return Err(());}rec.pending=true;}
                let body=if case.recovery(){json!({"intent":"recover","projectId":project})}else{json!({"intent":"edit","projectId":project,
                    "selection":{"platform":if case==Case::Ios{"ios"}else{"android"},"target":if case==Case::Ios{"Reader"}else{":app"},
                        "project":if case==Case::Ios{Some("iosApp/Reader.xcodeproj")}else{None}}})};
                let raw=serde_json::to_vec(&body).map_err(|_|())?;
                let args=commands::open(&raw).map_err(|_|())?;
                let result=state.bridge.open_project_identity(&state.document,window,args).map_err(|_|())?;
                let mut r=self.record().ok_or(())?;let rec=r.identity.as_mut().ok_or(())?;rec.status(&result)?;
                let opened=result.active.ok_or(())?;
                if opened.project_id!=project||opened.intent!=case.intent()||opened.phase!=edit::Phase::Opening
                    ||opened.owner_generation!=result.window_generation||!edit::token(&opened.session_id)
                    ||rec.sessions.iter().any(|s|s.projection.session_id==opened.session_id){return Err(());}
                rec.sessions.push(Session{projection:opened,opened:true,prepared:false,reviewed:false,submitted:false,closed:case.close(round),readback:false,finality:None});
                rec.pending=false;Step::WaitOpen
            },
            Step::WaitOpen|Step::WaitReview|Step::WaitFinal=>{
                let p=p.ok_or(())?;
                {let mut r=self.record().ok_or(())?;let s=r.identity.as_mut().ok_or(())?.sessions.last_mut().ok_or(())?;
                    if !same(&s.projection,&p)||p.late_settled||p.native_finality==edit::NativeFinality::Unknown{return Err(());}s.projection=p.clone();}
                if step==Step::WaitOpen {
                    if p.phase==edit::Phase::Opening{return Ok(());}if p.phase!=edit::Phase::Editing||!observed(case,&p){return Err(());}Step::Prepare
                }else if step==Step::WaitReview {
                    if p.phase==edit::Phase::Preparing{return Ok(());}if !reviewed(case,&p){return Err(());}
                    let mut r=self.record().ok_or(())?;r.fixture.identity.as_ref().ok_or(())?.verify(&r.fixture.root,r.fixture.uid)?;
                    r.identity.as_mut().ok_or(())?.sessions.last_mut().ok_or(())?.reviewed=true;Step::Submit
                }else{
                    if p.phase!=edit::Phase::Final{return Ok(());}
                    let f=state.bridge.edits.installed_identity_observation_final(&p.session_id).ok_or(())?;
                    let mut r=self.record().ok_or(())?;let closed=r.identity.as_ref().ok_or(())?.sessions.last().ok_or(())?.closed;
                    if !finality(&f,&p,closed,case){return Err(());}
                    let root=r.fixture.root.clone();let uid=r.fixture.uid;r.fixture.identity.as_mut().ok_or(())?.after(&root,uid,closed)?;
                    let rec=r.identity.as_mut().ok_or(())?;let s=rec.sessions.last_mut().ok_or(())?;s.finality=Some(f);s.readback=true;
                    if rec.sessions.len()<case.sessions(){Step::Open}else{Step::Done}
                }
            },
            Step::Prepare|Step::Submit=>{
                let p=p.ok_or(())?;
                let closed={let mut r=self.record().ok_or(())?;let rec=r.identity.as_mut().ok_or(())?;let s=rec.sessions.last().ok_or(())?;
                    if !same(&p,&s.projection)||(step==Step::Prepare&&(s.prepared||p.phase!=edit::Phase::Editing||!observed(case,&p)))
                        ||(step==Step::Submit&&(s.submitted||!s.reviewed||!reviewed(case,&p))){return Err(());}let closed=s.closed;rec.pending=true;closed};
                let c=p.checkout.as_ref().ok_or(())?;
                let result=if step==Step::Prepare{
                    let mut body=json!({"intent":case.intent(),"sessionId":p.session_id,"revision":c.revision});
                    if !case.recovery(){body["desiredIdentity"]=json!(NEW);body["identityIntent"]=json!("new-application");}
                    let raw=serde_json::to_vec(&body).map_err(|_|())?;let args=commands::prepare(&raw).map_err(|_|())?;
                    state.bridge.prepare_project_identity(&state.document,window,args)
                }else if closed{
                    let raw=serde_json::to_vec(&json!({"sessionId":p.session_id})).map_err(|_|())?;
                    let args=commands::close(&raw).map_err(|_|())?;state.bridge.edits.close_identity(window,&args.session_id)
                }else{
                    let plan=p.prepared.as_ref().ok_or(())?;let raw=serde_json::to_vec(&json!({"intent":case.intent(),"sessionId":p.session_id,
                        "revision":c.revision,"planToken":plan.plan_token})).map_err(|_|())?;
                    let args=commands::apply(&raw).map_err(|_|())?;state.bridge.apply_project_identity(&state.document,window,args)
                }.map_err(|_|())?;
                let mut r=self.record().ok_or(())?;let rec=r.identity.as_mut().ok_or(())?;rec.status(&result)?;
                let returned=result.active.as_ref().or(result.last_terminal.as_ref()).ok_or(())?;
                let s=rec.sessions.last_mut().ok_or(())?;if !same(&p,returned){return Err(());}s.projection=returned.clone();
                if step==Step::Prepare{s.prepared=true;}else{s.submitted=true;}rec.pending=false;
                if step==Step::Prepare{Step::WaitReview}else{Step::WaitFinal}
            },
            Step::Done=>{let mut r=self.record().ok_or(())?;if r.identity.as_ref().is_none_or(|s|!s.complete()){return Err(());}
                r.fixture.verify(false)?;r.file_readback=true;r.step=super::Step::Close;return Ok(());},
        };
        if !self.timely(){return Err(());}let mut r=self.record().ok_or(())?;
        if r.step!=super::Step::Identity(step){return Err(());}r.step=super::Step::Identity(next);Ok(())
    }
}

pub(super) fn data_checks()->bool{
    NAMES.iter().all(|name|Case::parse(name).is_some())&&Case::parse("identity-android-apply-extra").is_none()
        &&Case::Android.sessions()==2&&Case::Rollback.recovery()&&Case::Committed.recovery()&&!Case::Ios.recovery()
        &&files(Case::Committed,false).get(ANDROID_PATH)==files(Case::Committed,true).get(ANDROID_PATH)
        &&files(Case::Rollback,true).get(ANDROID_PATH)==Some(&SOURCE.to_vec())
        &&[Case::Android,Case::Ios,Case::Rollback,Case::Committed].iter().all(|c|
            directories(&files(*c,false),&controls(*c,false)).is_ok())
}

// Public literal fixtures mirrored by tools/macos_identity_qualification.py.
const SOURCE: &[u8] = br###"plugins { id("com.android.application") }
android {
 namespace = "com.example.source"
 defaultConfig {
  applicationId = "com.example.reader"
  versionCode = 1
 }
 buildTypes { debug { applicationIdSuffix = ".debug" } }
}
"###;
const PBX: &[u8] = br###"// !$*UTF8*$!
{ archiveVersion = 1; objectVersion = 56; objects = {
000000000000000000000001 = { isa = PBXProject; mainGroup = 000000000000000000000002; buildConfigurationList = 000000000000000000000004; targets = (000000000000000000000003,00000000000000000000000A); };
000000000000000000000002 = { isa = PBXGroup; sourceTree = "<group>"; children = (00000000000000000000000E); };
000000000000000000000004 = { isa = XCConfigurationList; buildConfigurations = (000000000000000000000005,000000000000000000000006); };
000000000000000000000005 = { isa = XCBuildConfiguration; name = Debug; buildSettings = {}; };
000000000000000000000006 = { isa = XCBuildConfiguration; name = Release; buildSettings = {}; };
000000000000000000000003 = { isa = PBXNativeTarget; name = Reader; productType = "com.apple.product-type.application"; buildConfigurationList = 000000000000000000000007; };
000000000000000000000007 = { isa = XCConfigurationList; buildConfigurations = (000000000000000000000008,000000000000000000000009); };
000000000000000000000008 = { isa = XCBuildConfiguration; name = Debug; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.reader; GENERATE_INFOPLIST_FILE = YES; }; };
000000000000000000000009 = { isa = XCBuildConfiguration; name = Release; baseConfigurationReference = 00000000000000000000000E; buildSettings = { GENERATE_INFOPLIST_FILE = YES; }; };
00000000000000000000000E = { isa = PBXFileReference; path = Config/Release.xcconfig; sourceTree = SOURCE_ROOT; };
00000000000000000000000A = { isa = PBXNativeTarget; name = ReaderTests; productType = "com.apple.product-type.bundle.unit-test"; buildConfigurationList = 00000000000000000000000B; };
00000000000000000000000B = { isa = XCConfigurationList; buildConfigurations = (00000000000000000000000C,00000000000000000000000D); };
00000000000000000000000C = { isa = XCBuildConfiguration; name = Debug; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.tests; }; };
00000000000000000000000D = { isa = XCBuildConfiguration; name = Release; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.tests; }; };
}; rootObject = 000000000000000000000001; }
"###;
const SCHEME: &[u8] = br###"<?xml version="1.0" encoding="UTF-8"?>
<Scheme version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
  <BuildActionEntries><BuildActionEntry buildForArchiving="YES" buildForRunning="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000003"
    ReferencedContainer="container:Reader.xcodeproj" BlueprintName="Reader" BuildableName="Reader.app"/>
  </BuildActionEntry></BuildActionEntries>
 </BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
"###;
const XCCONFIG: &[u8] = br###"// Literal release identity, owned only by Reader Release.
PRODUCT_BUNDLE_IDENTIFIER = com.example.reader
"###;
const ANDROID_CONFIG: &[u8] = br###"{
  "android": {
    "applicationId": "com.example.reader",
    "enabled": true,
    "identityStatus": "unverified",
    "module": ":app",
    "variant": "release"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"###;
const IOS_CONFIG: &[u8] = br###"{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "com.example.reader",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "iosApp/Reader.xcodeproj",
    "scheme": "Reader"
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"###;
