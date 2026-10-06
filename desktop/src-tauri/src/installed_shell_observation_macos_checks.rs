//! Two opt-in observations of ordinary UI handlers and their original owners.
//! No Start, cancellation, timer override or private owner is implemented here.
use super::*;
use crate::{environment_diagnostics_protocol as tools, offline_preflight_protocol as offline};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Case { Tools, Offline }
pub(super) const NAMES: [&str;2] = ["local-tool-observations","local-saved-offline"];
impl Case {
    pub(crate) fn name(self)->&'static str {NAMES[if self==Self::Tools {0}else{1}]}
    pub(crate) fn parse(s:&str)->Option<Self>{[Self::Tools,Self::Offline].into_iter().find(|c|c.name()==s)}
    pub(crate) fn seconds(self)->u64{if self==Self::Tools {90}else{1860}}
}
const DRAFT_BRANCH:&str="public-offline-draft";
const IDS_ANDROID:[&str;4]=["developer-selection","git","java","javac"];
const IDS_IOS:[&str;3]=["developer-selection","git","xcode"];
const STATUSES:[&str;9]=["PASS","FAIL","MISSING","BLOCKED","INVALID","SKIP","MANUAL","CONFIGURED","NOT_APPLICABLE"];
const LIMITATIONS:[&str;7]=["saved-inputs-not-atomic","project-code-effects-possible","not-network-isolated","core-builds-disabled",
    "artifact-validation-not-requested","toolkit-signing-credentials-store-not-requested","release-readiness-not-assessed"];
const CONSENT_TEXT:&str="I trust this project and understand that its saved checks may modify files, run programs, build, read account files or use the network; my unsaved draft is not used.";
pub(crate) fn config(case:Case)->Result<Vec<u8>,()>{if case==Case::Tools {local_edits::config(local_edits::Case::Metadata)}else{Ok(CONFIG.to_vec())}}
fn files(case:Case)->Result<BTreeMap<String,Vec<u8>>,()>{Ok(BTreeMap::from([
    (".gitignore".into(),super::Fixture::ignore_bytes(true,false)),("app/build.gradle.kts".into(),SOURCE.to_vec()),
    ("keep.txt".into(),KEEP.to_vec()),("release/mobile-release.json".into(),config(case)?),("version.properties".into(),VERSION.to_vec())]))}
const DIRS:[(&str,&[&str]);3]=[(".",&[".gitignore","app","keep.txt","release","version.properties"]),("app",&["build.gradle.kts"]),("release",&["mobile-release.json"])];
pub(super) struct Fixture {case:Case,files:BTreeMap<String,FileFact>,dirs:BTreeMap<String,[u64;6]>}
impl Fixture {
    pub(crate) fn capture(root:&Path,uid:u32,case:Case)->Result<Self,()>{
        let mut captured=BTreeMap::new();let mut dirs=BTreeMap::new();let expected=files(case)?;
        if expected.values().map(Vec::len).sum::<usize>()>65536{return Err(());}
        for(path,body)in expected{captured.insert(path.clone(),file_fact_mode(&root.join(path),&body,uid,0o600)?);}
        for(path,entries)in DIRS{dirs.insert(path.into(),directory(&root.join(path),uid,0o700,entries)?);}
        Ok(Self{case,files:captured,dirs})
    }
    pub(super) fn file(&self,path:&str)->Option<FileFact>{self.files.get(path).cloned()}
    pub(super) fn dir(&self,path:&str)->Option<[u64;6]>{self.dirs.get(path).copied()}
    pub(crate) fn verify(&self,root:&Path,uid:u32)->Result<(),()>{
        for(path,bytes)in files(self.case)?{if self.files.get(&path)!=Some(&file_fact_mode(&root.join(&path),&bytes,uid,0o600)?){return Err(());}}
        for(path,entries)in DIRS{if self.dir(path)!=Some(directory(&root.join(path),uid,0o700,entries)?){return Err(());}}Ok(())
    }
    fn summary(&self)->Option<Value>{let expected=files(self.case).ok()?;Some(json!({"files":5,"directories":3,
        "sha256":expected.iter().map(|(p,b)|(p.clone(),json!(digest(b)))).collect::<serde_json::Map<_,_>>() }))}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Step {Navigate,ToolsStart(u8),ToolsWait(u8),ToolsRead(u8),ToolsSelect,ToolsStale,
    EditBranch,EditedBranch,Releases,Prepare,Intent,Acknowledge,Acknowledged,Run,OfflineWait,OfflineRead,Settings,Discard,ConfirmDiscard,Discarded}
pub(super) enum Dom {Next(Step),Done}
#[derive(Default)]
struct Arrival {observed:bool,late:bool}
impl Arrival {
    fn observe(&mut self,elapsed:Duration)->Result<(),()>{
        if self.observed{return Err(());} self.observed=true;self.late=elapsed>Duration::from_secs(30);
        if self.late {Err(())}else{Ok(())}
    }
}
struct ToolRun {projection:Value,revision:u64,visible:bool,stale:bool}
pub(super) struct Record {
    case:Case,started:Instant,tools:Vec<ToolRun>,tool_pending:Option<Value>,tool_revision:u64,
    offline:Option<Value>,offline_revision:u64,prepare_pending:Option<Value>,prepared:bool,
    dirty:bool,acknowledged:bool,start:Arrival,start_returned:bool,offline_visible:bool,discarded:bool,readback:bool,
}
fn token(v:&Value)->bool{v.as_str().is_some_and(edit::token)}
fn number(v:&Value)->bool{v.as_u64().is_some_and(|n|n<u32::MAX as u64)}
fn same(p:&Value,q:&Value,key:&str)->bool{p[key]==q[key]&&p["ownerGeneration"]==q["ownerGeneration"]&&p["context"]==q["context"]}
fn tool_order(p:&Value)->Option<u8>{match p["phase"].as_str()?{"starting"=>Some(0),"checking"=>Some(1),"stopping"=>Some(2),"settled"=>Some(3),_=>None}}
fn offline_order(p:&Value)->Option<u8>{match p["phase"].as_str()?{"awaiting-consent"=>Some(0),"starting"=>Some(1),"running"=>Some(2),"stopping"=>Some(3),"terminal"=>Some(4),_=>None}}
fn tool_final(p:&Value)->bool{
    let result=&p["result"];let platform=p["context"]["platform"].as_str();
    let ids:&[&str]=match platform{Some("android")=>&IDS_ANDROID,Some("ios")=>&IDS_IOS,_=>return false};
    let Some(rows)=result["checks"].as_array()else{return false;};
    p["phase"]=="settled"&&p["finality"]=="settled"&&p["outcome"]=="complete"&&p["reason"]=="none"
        &&result["schemaVersion"]==1&&result["hostPlatform"]=="macos"&&result["outcome"]=="complete"&&result["context"]==p["context"]
        &&result["commandsAttempted"].as_u64().is_some_and(|n|(1..=4).contains(&n))
        &&rows.len()==ids.len()&&rows.iter().zip(ids).all(|(r,id)|r["id"]==*id)
        &&rows.iter().any(|r|r["id"]!="developer-selection"&&r["state"]=="completed"&&r["reason"]=="observed"&&r["returnCode"]==0&&r["version"].is_string())
        // Native phase/finality above, never these provisional core facts alone.
        &&result["assurance"]["releaseReadiness"]=="unknown"&&result["assurance"]["dependencyCompleteness"]=="unknown"
}
fn offline_final(p:&Value)->bool{
    let result=&p["result"];let Some(rows)=result["findings"].as_array()else{return false;};
    p["phase"]=="terminal"&&p["outcome"]=="complete"&&p["reason"]=="none"&&p["intentUsable"]==false
        &&result["schemaVersion"]==1&&result["scope"]=="saved-offline-android-no-core-build"
        &&result["usedConfig"]==p["context"]["savedConfig"]&&result["limitations"]==json!(LIMITATIONS)
        &&rows.len()<=128&&rows.len()==result["summary"]["shown"].as_u64().unwrap_or(u64::MAX)as usize
        &&[("android-gradle-wrapper","MISSING"),("version-source","PASS"),("workspace-private-output","PASS")].iter()
            .all(|(check,status)|rows.iter().any(|r|r["check"]==*check&&r["message"]==*check&&r["status"]==*status))
        &&rows.iter().all(|r|r["projectCheckIndex"].is_null()&&r["check"]!="configured-project-check")
}
fn context(project:&str,request:&Value,platform:&str,operation:&str)->Option<Value>{
    (request["projectId"]==project&&!project.is_empty()&&number(&request["draftRevision"])&&number(&request["baselineGeneration"]))
        .then(||json!({"projectId":project,"draftRevision":request["draftRevision"],"baselineGeneration":request["baselineGeneration"],"platform":platform,"operation":operation}))
}
impl Record {
    pub(crate) fn new(case:Case,started:Instant)->Self{Self{case,started,tools:Vec::with_capacity(2),tool_pending:None,tool_revision:0,
        offline:None,offline_revision:0,prepare_pending:None,prepared:false,dirty:false,acknowledged:false,start:Arrival::default(),
        start_returned:false,offline_visible:false,discarded:false,readback:false}}
    fn tools_request(&mut self,request:&Value,step:Option<Step>,project:&str,base:&Value)->Result<(),()>{
        let round=self.tools.len();if self.case!=Case::Tools||round>=2||self.tool_pending.is_some()
            ||!matches!(step,Some(Step::ToolsStart(i)|Step::ToolsWait(i))if usize::from(i)==round)
            ||self.tools.iter().any(|r|!r.visible||!r.stale||!tool_final(&r.projection))||request["draft"]!=*base{return Err(());}
        let platform=if round==0{"android"}else{"ios"};let c=context(project,request,platform,"build").ok_or(())?;
        if request["platform"]!=platform||request["operation"]!="build"{return Err(());}
        if let Some(first)=self.tools.first(){let mut prior=first.projection["context"].clone();prior["platform"]=json!(platform);if prior!=c{return Err(());}}
        self.tool_pending=Some(c);Ok(())
    }
    fn tools_status(&mut self,value:Value,returned:bool)->Result<(),()>{
        if value["schemaVersion"]!=1||!number(&value["statusRevision"]){return Err(());}
        let revision=value["statusRevision"].as_u64().ok_or(())?;
        if !returned&&self.tool_pending.is_some(){return Ok(());} // Do not adopt a broadcast before the actual Start reply.
        if !returned&&revision<self.tool_revision{return Ok(());} // Older passive reads never regress a newer original.
        let p=if value["active"].is_null(){&value["lastTerminal"]}else{&value["active"]};
        if returned{
            let c=self.tool_pending.take().ok_or(())?;
            if p["context"]!=c||!token(&p["runId"])||!token(&p["ownerGeneration"])||tool_order(p).is_none()
                ||self.tools.iter().any(|r|r.projection["runId"]==p["runId"])
                ||self.tools.first().is_some_and(|r|r.projection["ownerGeneration"]==p["ownerGeneration"]){return Err(());}
            self.tools.push(ToolRun{projection:p.clone(),revision,visible:false,stale:false});
        }else if let Some(run)=self.tools.last_mut(){
            if !same(&run.projection,p,"runId")||tool_order(p).is_none()||tool_order(p)<tool_order(&run.projection)
                ||tool_final(&run.projection)&&*p!=run.projection{return Err(());}run.projection=p.clone();run.revision=revision;
        }else if !p.is_null(){return Err(());}
        if p["finality"]=="unknown"||p["phase"]=="retained-unknown"{return Err(());}
        // A known terminal with no parsed version is prerequisite-unavailable,
        // not a positive journey. Fail now; do not burn the shutdown reserve.
        if p["phase"]=="settled"&&!tool_final(p){return Err(());}
        self.tool_revision=self.tool_revision.max(revision);Ok(())
    }
    fn prepare_request(&mut self,value:&Value,step:Option<Step>,project:&str)->Result<(),()>{
        if self.case!=Case::Offline||!self.dirty||self.prepared||self.prepare_pending.is_some()
            ||!matches!(step,Some(Step::Prepare|Step::Intent)){return Err(());}
        let mut c=context(project,value,"android","offline-preflight").ok_or(())?;
        let saved=json!({"bytes":CONFIG.len(),"sha256":digest(CONFIG)});if value["savedConfig"]!=saved{return Err(());}c["savedConfig"]=saved;
        self.prepare_pending=Some(c);Ok(())
    }
    fn start_request(&mut self,value:&Value,step:Option<Step>)->Result<(),()>{
        if self.case!=Case::Offline||!self.prepared||!self.acknowledged||!matches!(step,Some(Step::Run|Step::OfflineWait)){return Err(());}
        let p=self.offline.as_ref().ok_or(())?;
        if value!=&json!({"operationId":p["operationId"],"ownerGeneration":p["ownerGeneration"],"consentVersion":offline::CONSENT}){return Err(());}
        // Read-only observation AFTER real IPC arrival. An error does not stop
        // Document::start_offline_preflight: ordinary ownership remains intact.
        self.start.observe(self.started.elapsed())
    }
    fn offline_status(&mut self,value:Value,returned:Option<&str>)->Result<(),()>{
        if value["schemaVersion"]!=1||!number(&value["statusRevision"]){return Err(());}let revision=value["statusRevision"].as_u64().ok_or(())?;
        if returned.is_none()&&(self.prepare_pending.is_some()||self.start.observed&&!self.start_returned){return Ok(());}
        if returned.is_none()&&revision<self.offline_revision{return Ok(());}
        let p=&value["operation"];
        if returned==Some("prepare"){
            let c=self.prepare_pending.take().ok_or(())?;
            if self.prepared||p["context"]!=c||!token(&p["operationId"])||!token(&p["ownerGeneration"])||p["phase"]!="awaiting-consent"
                ||p["intentUsable"]!=true||!p["outcome"].is_null()||!p["result"].is_null(){return Err(());}self.prepared=true;
        }else if let Some(old)=&self.offline{
            if !same(old,p,"operationId")||offline_order(p).is_none()||offline_order(p)<offline_order(old)
                ||offline_final(old)&&*p!=*old{return Err(());}
        }else if !p.is_null(){return Err(());}
        if returned==Some("start"){
            if !self.start.observed||self.start.late||self.start_returned||p["intentUsable"]!=false
                ||!matches!(p["phase"].as_str(),Some("starting"|"running"|"stopping"|"terminal")){return Err(());}self.start_returned=true;
        }
        if p["phase"]=="unknown"||p["phase"]=="terminal"&&!offline_final(p){return Err(());}if !p.is_null(){self.offline=Some(p.clone());}
        self.offline_revision=self.offline_revision.max(revision);Ok(())
    }
    pub(super) fn waiting(&self,step:Step)->bool{match step{
        Step::ToolsWait(i)=>self.tools.get(usize::from(i)).is_none_or(|r|!tool_final(&r.projection)),
        Step::Intent=>!self.prepared,
        Step::OfflineWait=>!self.start_returned||self.offline.as_ref().is_none_or(|p|!offline_final(p)),_=>false}}
    pub(super) fn pre_dispatch(&self,step:Step)->bool{step!=Step::Run||self.started.elapsed()<=Duration::from_secs(30)}
    pub(super) fn next_wait(step:Step)->Step{match step{Step::ToolsWait(i)=>Step::ToolsRead(i),Step::OfflineWait=>Step::OfflineRead,other=>other}}
    pub(super) fn dom(&mut self,step:Step,v:&Value)->Result<Dom,()>{
        let ready=json!({"state":"ready"});
        let next=match step{
            Step::Navigate=>if self.case==Case::Tools{Step::ToolsStart(0)}else{Step::EditBranch},
            Step::ToolsStart(i)=>Step::ToolsWait(i),
            Step::ToolsRead(i)=>{let r=self.tools.get_mut(usize::from(i)).ok_or(())?;
                if r.visible||!tool_final(&r.projection)||*v!=json!({"state":"ready","render":tool_render(&r.projection,false).ok_or(())?}){return Err(());}r.visible=true;
                return if i==0{Ok(Dom::Next(Step::ToolsSelect))}else{Ok(Dom::Done)};},
            Step::ToolsSelect=>Step::ToolsStale,
            Step::ToolsStale=>{let r=self.tools.first_mut().ok_or(())?;if !r.visible||r.stale||*v!=json!({"state":"ready","render":tool_render(&r.projection,true).ok_or(())?}){return Err(());}r.stale=true;return Ok(Dom::Next(Step::ToolsStart(1)));},
            Step::EditBranch=>Step::EditedBranch,
            Step::EditedBranch=>{if *v!=json!({"state":"ready","branch":DRAFT_BRANCH,"dirty":true}){return Err(());}self.dirty=true;return Ok(Dom::Next(Step::Releases));},
            Step::Releases=>Step::Prepare,Step::Prepare=>Step::Intent,
            Step::Intent=>{if !self.prepared||*v!=json!({"state":"ready","savedBytes":CONFIG.len(),"disclosure":true,"acknowledged":false}){return Err(());}return Ok(Dom::Next(Step::Acknowledge));},
            Step::Acknowledge=>Step::Acknowledged,
            Step::Acknowledged=>{if !self.prepared||self.acknowledged||*v!=json!({"state":"ready","acknowledged":true}){return Err(());}self.acknowledged=true;return Ok(Dom::Next(Step::Run));},
            Step::Run=>Step::OfflineWait,
            Step::OfflineRead=>{let p=self.offline.as_ref().ok_or(())?;if !self.start_returned||self.start.late||!offline_final(p)
                ||*v!=json!({"state":"ready","render":offline_render(p).ok_or(())?}){return Err(());}self.offline_visible=true;return Ok(Dom::Next(Step::Settings));},
            Step::Settings=>Step::Discard,Step::Discard=>Step::ConfirmDiscard,Step::ConfirmDiscard=>Step::Discarded,
            Step::Discarded=>{if !self.offline_visible||*v!=json!({"state":"ready","branch":"main","dirty":false}){return Err(());}self.discarded=true;return Ok(Dom::Done);},
            _=>return Err(())};
        if *v!=ready{return Err(());}Ok(Dom::Next(next))
    }
    fn complete(&self)->bool{match self.case{
        Case::Tools=>self.tools.len()==2&&self.tool_pending.is_none()&&self.tools.iter().all(|r|r.visible&&tool_final(&r.projection))&&self.tools[0].stale,
        Case::Offline=>self.dirty&&self.prepared&&self.acknowledged&&self.start.observed&&!self.start.late&&self.start_returned&&self.offline_visible&&self.discarded&&self.offline.as_ref().is_some_and(offline_final)}}
    pub(super) fn readback(&mut self)->Result<(),()>{if !self.complete()||self.readback{return Err(());}self.readback=true;Ok(())}
    pub(super) fn report(&self,fixture:&Fixture)->Option<Value>{
        if !self.complete()||!self.readback||self.case!=fixture.case{return None;}
        let tools=self.tools.iter().map(|r|{let p=&r.projection;json!({"runId":p["runId"],"ownerGeneration":p["ownerGeneration"],"context":p["context"],
            "statusRevision":r.revision,"phase":p["phase"],"finality":p["finality"],"outcome":p["outcome"],"commandsAttempted":p["result"]["commandsAttempted"],
            "checks":p["result"]["checks"].as_array().expect("validated typed report").iter().map(|row|{let mut r=row.clone();r.as_object_mut().expect("typed check").remove("help");r.as_object_mut().expect("typed check").remove("selectionDiagnostic");r}).collect::<Vec<_>>(),
            "sameOriginal":true,"rendered":r.visible,"staleAfterContextChange":r.stale})}).collect::<Vec<_>>();
        let offline=self.offline.as_ref().map(|p|json!({"operationId":p["operationId"],"ownerGeneration":p["ownerGeneration"],"context":p["context"],
            "statusRevision":self.offline_revision,"phase":p["phase"],"outcome":p["outcome"],"result":p["result"],
            "sameOriginal":true,"dirtyDraftObserved":self.dirty,"explicitConsent":self.acknowledged,"startArrivalObserved":self.start.observed,
            "startArrivalLate":self.start.late,"rendered":self.offline_visible,"draftDiscardedThroughUi":self.discarded}));
        Some(json!({"schemaVersion":1,"case":self.case.name(),"tools":tools,"offline":offline,"sameOriginalNativeTerminals":true,
            "exactFixtureReadback":true,"fixture":fixture.summary()?,"releaseReadiness":"not-assessed","physicalDropdownGestureTested":false}))
    }
}

// Taps never return a gate to the IPC caller and never call ordinary Start.
impl Observation {
    pub(crate) fn checks_case(&self)->bool{matches!(self.case,super::Case::Checks(_))}
    fn checks(&self,f:impl FnOnce(&mut Record,Option<Step>,&str)->Result<(),()>){
        if !self.checks_case(){return;}if !self.timely(){return;}
        let Some(mut parent)=self.record()else{return;};let project=parent.project.as_ref().map(|p|p.id.clone()).unwrap_or_default();
        let step=if let super::Step::Checks(s)=parent.step{Some(s)}else{None};
        if parent.checks.as_mut().ok_or(()).and_then(|r|f(r,step,&project)).is_err(){self.fail_with("local-checks-original-contract");}else{self.timely();}
    }
    pub(crate) fn checks_tools_request(&self,request:&Value){self.checks(|r,step,project|r.tools_request(request,step,project,&self.base));}
    pub(crate) fn checks_tools_result(&self,result:&Result<tools::Status,BridgeError>,returned:bool){
        if self.case!=super::Case::Checks(Case::Tools){return;}
        self.checks(|r,_,_|r.tools_status(serde_json::to_value(result.as_ref().map_err(|_|())?).map_err(|_|())?,returned));
    }
    pub(crate) fn checks_prepare_request(&self,request:&Value){self.checks(|r,step,project|r.prepare_request(request,step,project));}
    pub(crate) fn checks_start_request(&self,request:&Value){self.checks(|r,step,_|r.start_request(request,step));}
    pub(crate) fn checks_offline_result(&self,result:&Result<offline::Status,BridgeError>,returned:Option<&str>){
        if self.case!=super::Case::Checks(Case::Offline){return;}
        self.checks(|r,_,_|r.offline_status(serde_json::to_value(result.as_ref().map_err(|_|())?).map_err(|_|())?,returned));
    }
    pub(crate) fn checks_cancel_request(&self){if self.checks_case(){self.fail_with("local-checks-unexpected-cancel");}}
}
fn text_for<'a>(pairs:&'a[(&str,&str)],key:&Value)->Option<&'a str>{pairs.iter().find(|(k,_)|Some(*k)==key.as_str()).map(|(_,v)|*v)}
fn display_version(value:&Value,build:&Value,absent:&str)->Option<String>{
    let mut result=if value.is_null(){absent.to_owned()}else{value.as_str()?.to_owned()};
    if !build.is_null(){result.push_str(" · build ");result.push_str(build.as_str()?);}Some(result)
}
fn tool_render(p:&Value,stale:bool)->Option<Value>{
    if !tool_final(p){return None;}let context=&p["context"];
    let rows=p["result"]["checks"].as_array()?.iter().map(|r|Some(json!({
        "label":text_for(TOOL_LABELS,&r["id"])?,"state":r["state"],"assessment":r["assessment"],"reason":text_for(TOOL_REASONS,&r["reason"])?,
        "observed":display_version(&r["version"],&r["build"],"Not assessed")?,
        "baselineLabel":match r["baseline"]["kind"].as_str()?{"workflow-reference"=>"Workflow reference · not a local compatibility rule","exact-pin"=>"Expected exact core baseline · not the observation","no-local-policy"=>"No local version policy",_=>return None},
        "baseline":display_version(&r["baseline"]["version"],&r["baseline"]["build"],"No version requirement inferred")?,
        "exit":if r["returnCode"].is_null(){None}else{Some(r["returnCode"].as_i64()?.to_string())}
    }))).collect::<Option<Vec<_>>>()?;
    Some(json!({"heading":if stale{"Earlier / stale tool observations"}else{"Tool observations from this run"},
        "context":format!("{} / build · draft {} · baseline {} · core host macos",if context["platform"]=="android"{"Android"}else{"iOS"},context["draftRevision"].as_u64()?,context["baselineGeneration"].as_u64()?),
        "badges":["Phase: settled","Outcome: complete","Native finality: settled"],"acknowledged":true,"stale":stale,"rows":rows,"limits":true}))
}
fn offline_render(p:&Value)->Option<Value>{
    if !offline_final(p){return None;}let result=&p["result"];let summary=&result["summary"];
    let findings=result["findings"].as_array()?.iter().map(|r|Some(json!({"ordinal":r["ordinal"],"status":r["status"],"message":text_for(FINDING_TEXT,&r["message"])?}))).collect::<Option<Vec<_>>>()?;
    Some(json!({"phase":"Original operation settled","outcome":"Outcome: complete","current":"This invocation only", "limits":true,
        "summary":summary,"findings":findings,"limitations":LIMITATIONS.iter().map(|key|text_for(LIMIT_TEXT,&json!(key))).collect::<Option<Vec<_>>>()?,
        "filter":"all","visible":summary["shown"],"reported":summary["total"],"omitted":summary["omitted"]}))
}

pub(super) fn script(case:Case,step:Step)->Option<String>{
    let body=match step{
        Step::Navigate=>if case==Case::Tools {"return nav('Environment');"}else{"return nav('Project settings');"}.to_owned(),
        Step::ToolsStart(i)=>{if i>1{return None;}format!(r#"if(!selected('Environment'))return wait();platform({i});const s=tools(),b=button(s,'Check build tools');if(b.disabled)return wait();click(b);return ready();"#)},
        Step::ToolsRead(_)=>"if(!selected('Environment'))return wait();return toolReport(false);".into(),
        Step::ToolsSelect=>r#"const s=platform(0);show(s);s.selectedIndex=1;s.dispatchEvent(new Event('change',{bubbles:true}));return ready();"#.into(),
        Step::ToolsStale=>"platform(1);return toolReport(true);".into(),
        Step::EditBranch=>r#"if(!selected('Project settings'))return wait();const e=branch();if(e.value!=='main')throw 0;show(e);e.focus();e.select();if(!document.execCommand('insertText',false,'public-offline-draft')||e.value!=='public-offline-draft')throw 0;return ready();"#.into(),
        Step::EditedBranch=>"return draft('public-offline-draft',true);".into(),
        Step::Releases=>"return nav('Releases');".into(),
        Step::Prepare=>r#"if(!selected('Releases'))return wait();const s=offline(),b=button(s,'Review offline checks');if(![...s.querySelectorAll('strong')].some(e=>text(e)==='Unsaved draft changes are NOT used.'))throw 0;if(b.disabled)return wait();click(b);return ready();"#.into(),
        Step::Intent=>r#"const s=offline();if(!s.querySelector('[role="group"][aria-label="Confirm this saved offline-check intent"]'))return wait();const g=intent(),i=g.querySelector('input[type="checkbox"]'),p=g.querySelector(':scope > p');if(!i||!p||i.disabled)throw 0;show(g);const m=text(p).match(/Saved comparison: ([0-9]+) bytes\./);if(!m)throw 0;return {state:'ready',savedBytes:Number(m[1]),disclosure:text(g.querySelector('.offline-ack span'))===consent,acknowledged:i.checked};"#.into(),
        Step::Acknowledge=>r#"const g=intent(),i=g.querySelector('input[type="checkbox"]');if(!i||i.disabled||i.checked||text(g.querySelector('.offline-ack span'))!==consent)throw 0;click(i);return ready();"#.into(),
        Step::Acknowledged=>r#"const g=intent(),i=g.querySelector('input[type="checkbox"]'),b=button(g,'Run saved offline checks');if(!i||!i.checked||i.disabled||b.disabled)return wait();return {state:'ready',acknowledged:true};"#.into(),
        Step::Run=>r#"const g=intent(),i=g.querySelector('input[type="checkbox"]'),b=button(g,'Run saved offline checks');if(!i||!i.checked||i.disabled||b.disabled)throw 0;click(b);return ready();"#.into(),
        Step::OfflineRead=>"return offlineReport();".into(),
        Step::Settings=>"return nav('Project settings');".into(),
        Step::Discard=>r#"if(!selected('Project settings'))return wait();if(branch().value!=='public-offline-draft')throw 0;const b=button(document.querySelector('.draft-toolbar'),'Discard draft changes');if(b.disabled)throw 0;click(b);return ready();"#.into(),
        Step::ConfirmDiscard=>r#"const ds=document.querySelectorAll('dialog.confirm-dialog[open]');if(ds.length!==1)return wait();const d=ds[0];if(text(d.querySelector('h2'))!=='Discard this in-memory draft?')throw 0;click(button(d,'Discard draft'));return ready();"#.into(),
        Step::Discarded=>r#"if(document.querySelector('dialog[open]'))return wait();return draft('main',false);"#.into(),
        _=>return None};
    Some([r#"(() => {try {
        const text=e=>e?.textContent?.trim()??'',wait=()=>({state:'wait'}),ready=()=>({state:'ready'});
        const show=e=>{if(!e)throw 0;e.scrollIntoView({block:'center'});const r=e.getBoundingClientRect(),s=getComputedStyle(e);if(r.width<=0||r.height<=0||s.display==='none'||s.visibility==='hidden')throw 0;};
        const button=(s,name)=>{if(!s)throw 0;const a=[...s.querySelectorAll('button')].filter(b=>text(b)===name);if(a.length!==1)throw 0;return a[0];};
        const click=b=>{if(!b||b.disabled)throw 0;show(b);b.click();};
        const selected=name=>document.querySelector(`nav[aria-label="Workspace navigation"] button[aria-label="${name}"]`)?.getAttribute('aria-current')==='page';
        const nav=name=>{if(document.querySelector('dialog[open]'))throw 0;const b=document.querySelector(`nav[aria-label="Workspace navigation"] button[aria-label="${name}"]`);if(!b||b.disabled)throw 0;click(b);return ready();};
        const tools=()=>{const a=document.querySelectorAll('[aria-label="Observed build-tool checks"]');if(a.length!==1)throw 0;return a[0];};
        const platform=i=>{const s=document.querySelector('#environment-platform'),op=document.querySelector('#environment-operation');if(!s||s.disabled||s.options.length!==2||!op||op.disabled||op.value!=='build')throw 0;
            if([...s.options].some((o,k)=>o.disabled||o.value!==['android','ios'][k]||text(o)!==['Android','iOS'][k])||s.selectedIndex!==i||s.value!==['android','ios'][i])throw 0;show(s);return s;};
        const toolReport=stale=>{const s=tools(),title=stale?'Earlier / stale tool observations':'Tool observations from this run';
            const hs=[...s.querySelectorAll('.section-heading h2')].filter(e=>text(e)===title);if(hs.length!==1)return wait();
            const blocks=[...s.querySelectorAll(':scope > .button-row')].filter(e=>e.querySelectorAll(':scope > .badge').length===3);if(blocks.length!==1)return wait();
            const cards=[...s.querySelectorAll('.environment-requirements > article.tool-card')];if(cards.length<3||cards.length>4)throw 0;
            const rows=cards.map(c=>{show(c);const bs=[...c.querySelectorAll(':scope > .button-row > .badge')],dl=c.querySelector(':scope > dl.environment-baseline');
                const dt=dl?[...dl.querySelectorAll(':scope > dt')]:[],dd=dl?[...dl.querySelectorAll(':scope > dd')]:[];
                if(bs.length!==2||dt.length!==dd.length||![2,3].includes(dt.length)||text(dt[0])!=='Observed version'||dt.length===3&&text(dt[2])!=='Complete command exit code')throw 0;
                return {label:text(c.querySelector(':scope > h3')),state:text(bs[0]),assessment:text(bs[1]),reason:text(c.querySelector(':scope > p')),observed:text(dd[0]),baselineLabel:text(dt[1]),baseline:text(dd[1]),exit:dd.length===3?text(dd[2]):null};});
            const acknowledged=[...s.querySelectorAll(':scope > .save-note')].some(e=>text(e).includes(' · acknowledged original Start. Receipt time is not a native deadline or a fresh probe.'));
            const actualStale=[...s.querySelectorAll(':scope > .review-caution')].some(e=>text(e)==='These rows belong to an earlier or unconfirmed project, draft, selection, activity or connection context. Returning to the same project does not refresh them.');
            return {state:'ready',render:{heading:text(hs[0]),context:text(hs[0].parentElement.querySelector('p')),badges:[...blocks[0].querySelectorAll(':scope > .badge')].map(text),acknowledged,stale:actualStale,rows,
                limits:[...s.querySelectorAll('strong')].some(e=>text(e)==='Complete means the finite check roster finished, not that every tool matched.')}};};
        const branch=()=>{const a=document.querySelectorAll('.form-field .help-button[aria-label="Help: Candidate branch"]');if(a.length!==1)throw 0;const field=a[0].closest('.form-field'),l=field.querySelector('label'),e=field.querySelector('input[type="text"]');if(!e||e.disabled||e.readOnly||l?.htmlFor!==e.id)throw 0;return e;};
        const draft=(value,dirty)=>{if(!selected('Project settings'))return wait();const e=branch(),b=document.querySelector('.draft-banner > .badge');if(e.value!==value||text(b)!==(dirty?'Unsaved changes':'Unchanged draft'))return wait();show(e);show(b);return {state:'ready',branch:e.value,dirty};};
        const offline=()=>{if(!selected('Releases'))throw 0;const a=document.querySelectorAll('.offline-preflight');if(a.length!==1)throw 0;return a[0];};
        const intent=()=>{const a=offline().querySelectorAll('[role="group"][aria-label="Confirm this saved offline-check intent"]');if(a.length!==1)throw 0;return a[0];};
        const consent="#, &serde_json::to_string(CONSENT_TEXT).ok()?,r#";
        const offlineReport=()=>{const s=offline(),r=s.querySelector('[aria-label="Saved offline check findings"]');if(!r)return wait();
            const ps=[...r.querySelectorAll(':scope > p')],sum=ps.map(text).map(t=>t.match(/^([0-9]+) total findings · ([0-9]+) included in the returned list · ([0-9]+) omitted from that list\. Counts below include every reported finding\.$/)).filter(Boolean);if(sum.length!==1)throw 0;
            const counts=Object.create(null),rows=[...r.querySelectorAll('.offline-counts > div')];if(rows.length!==9)throw 0;for(const row of rows){const k=text(row.querySelector('dt')),v=text(row.querySelector('dd'));if(k in counts||! /^(0|[1-9][0-9]*)$/.test(v))throw 0;counts[k]=Number(v);}
            const f=r.querySelector('.form-field select'),expected=['all','PASS','FAIL','MISSING','BLOCKED','INVALID','SKIP','MANUAL','CONFIGURED','NOT_APPLICABLE'];if(!f||f.disabled||f.options.length!==10||[...f.options].some((o,i)=>o.value!==expected[i]||o.disabled)||f.value!=='all')throw 0;
            const findings=[...r.querySelectorAll('.offline-findings > li')].map(li=>{show(li);const b=li.querySelector(':scope > .badge'),sp=[...li.querySelectorAll(':scope > span')].filter(e=>!e.classList.contains('badge'));if(!b||sp.length!==1)throw 0;return {ordinal:li.value-1,status:text(b),message:text(sp[0])};});if(findings.length>128)throw 0;
            const progress=s.querySelector(':scope > .session-progress'),outcomes=progress?[...progress.querySelectorAll(':scope > p')].filter(e=>e.querySelector('strong')):[];
            const shown=r.querySelector(':scope > [role="status"] > p'),match=text(shown).match(/^([0-9]+) visible of ([0-9]+) reported findings · ([0-9]+) omitted from the returned list\.$/);if(!match||outcomes.length!==1)throw 0;
            const m=sum[0];return {state:'ready',render:{phase:text(progress.querySelector('.inline-heading .badge')),outcome:text(outcomes[0]),current:text(r.querySelector(':scope > .inline-heading .badge')),
                limits:ps.some(p=>text(p.querySelector('strong'))==='Complete is not PASS or release readiness.'),summary:{total:Number(m[1]),shown:Number(m[2]),omitted:Number(m[3]),counts},findings,
                limitations:[...r.querySelectorAll(':scope > ul > li')].map(text),filter:f.value,visible:Number(match[1]),reported:Number(match[2]),omitted:Number(match[3])}};};
    "#,&body,r#"} catch {return {state:'error'};} })()"#].concat())
}

pub(super) fn data_checks()->bool{
    let mut arrival=Arrival::default();let late=arrival.observe(Duration::from_secs(31));
    late.is_err()&&arrival.observed&&arrival.late&&NAMES.len()==2&&STATUSES.len()==9&&LIMITATIONS.len()==7
        &&Case::Tools.seconds()==90&&Case::Offline.seconds()==1860
        &&!tool_final(&json!({"phase":"settled","finality":"unknown"}))&&!offline_final(&json!({"phase":"terminal","outcome":"complete"}))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tool() -> Value {
        json!({"runId":"11111111111111111111111111111111","ownerGeneration":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "context":{"projectId":"public-project","draftRevision":0,"baselineGeneration":1,"platform":"android","operation":"build"},
            "phase":"settled","finality":"settled","outcome":"complete","reason":"none","result":{
                "schemaVersion":1,"hostPlatform":"macos","outcome":"complete","context":{"projectId":"public-project","draftRevision":0,"baselineGeneration":1,"platform":"android","operation":"build"},
                "commandsAttempted":2,"checks":[{"id":"developer-selection"},{"id":"git","state":"completed","reason":"observed","returnCode":0,"version":"2.49.0"},{"id":"java"},{"id":"javac"}],
                "assurance":{"releaseReadiness":"unknown","dependencyCompleteness":"unknown"}}})
    }
    fn prepared() -> Value {
        json!({"operationId":"33333333333333333333333333333333","ownerGeneration":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "context":{"projectId":"public-project","draftRevision":1,"baselineGeneration":1,"platform":"android","operation":"offline-preflight",
                "savedConfig":{"bytes":CONFIG.len(),"sha256":digest(CONFIG)}},
            "phase":"awaiting-consent","outcome":null,"reason":"none","intentUsable":true,"result":null})
    }
    fn terminal() -> Value {
        let mut p=prepared();p["phase"]=json!("terminal");p["outcome"]=json!("complete");p["intentUsable"]=json!(false);
        p["result"]=json!({"schemaVersion":1,"scope":"saved-offline-android-no-core-build","usedConfig":p["context"]["savedConfig"],
            "findings":[{"ordinal":0,"check":"version-source","message":"version-source","status":"PASS","projectCheckIndex":null},
                {"ordinal":1,"check":"android-gradle-wrapper","message":"android-gradle-wrapper","status":"MISSING","projectCheckIndex":null},
                {"ordinal":2,"check":"workspace-private-output","message":"workspace-private-output","status":"PASS","projectCheckIndex":null}],
            "summary":{"total":3,"shown":3,"omitted":0,"counts":{"PASS":2,"MISSING":1,"FAIL":0,"BLOCKED":0,"INVALID":0,"SKIP":0,"MANUAL":0,"CONFIGURED":0,"NOT_APPLICABLE":0}},
            "limitations":LIMITATIONS});p
    }
    fn status(p:Value,revision:u32)->Value{json!({"schemaVersion":1,"statusRevision":revision,"operation":p})}
    #[test]
    fn actual_context_and_terminal_are_required(){
        assert!(data_checks());let mut a=Arrival::default();assert!(a.observe(Duration::from_secs(30)).is_ok());assert!(a.observe(Duration::ZERO).is_err());
        let mut late=Arrival::default();assert!(late.observe(Duration::from_secs(31)).is_err());
        // It WAS observed arriving. The ordinary call is not gated; late is
        // never represented as an unstarted original or cleanup permission.
        assert!(late.observed&&late.late);
        let base=json!({"public-test-data":true});let projection=tool();let request=json!({"projectId":"public-project","draftRevision":0,"baselineGeneration":1,"platform":"android","operation":"build","draft":base});
        for wrong in ["project","context","generation"] {
            let mut r=Record::new(Case::Tools,Instant::now());
            r.tools_request(&request,Some(Step::ToolsStart(0)),"public-project",&base).unwrap();
            let mut p=projection.clone();
            match wrong {"project"=>p["context"]["projectId"]=json!("other"),"context"=>p["context"]["platform"]=json!("ios"),_=>p["ownerGeneration"]=Value::Null}
            assert!(r.tools_status(json!({"schemaVersion":1,"statusRevision":2,"active":null,"lastTerminal":p}),true).is_err());assert!(!r.complete());
        }
        let mut r=Record::new(Case::Tools,Instant::now());
        r.tools_request(&request,Some(Step::ToolsStart(0)),"public-project",&base).unwrap();
        assert!(r.tools_request(&request,Some(Step::ToolsStart(0)),"public-project",&base).is_err());
        r.tools_status(json!({"schemaVersion":1,"statusRevision":2,"active":null,"lastTerminal":projection}),true).unwrap();
        assert!(!r.waiting(Step::ToolsWait(0)));assert!(!r.complete());
        let mut replaced=tool();replaced["runId"]=json!("22222222222222222222222222222222");
        assert!(r.tools_status(json!({"schemaVersion":1,"statusRevision":3,"active":null,"lastTerminal":replaced}),false).is_err());
        // The real registry makes both tokens fresh for EVERY original. The
        // first terminal remains a different original, not a lifetime token.
        for reused_generation in [false,true] {
            let mut second=Record::new(Case::Tools,Instant::now());
            second.tools_request(&request,Some(Step::ToolsStart(0)),"public-project",&base).unwrap();
            second.tools_status(json!({"schemaVersion":1,"statusRevision":2,"active":null,"lastTerminal":tool()}),true).unwrap();
            // Inert unit DATA for the already-observed first rendered/stale UI.
            second.tools[0].visible=true;second.tools[0].stale=true;
            let mut ios_request=request.clone();ios_request["platform"]=json!("ios");
            second.tools_request(&ios_request,Some(Step::ToolsStart(1)),"public-project",&base).unwrap();
            let mut ios=tool();ios["runId"]=json!("22222222222222222222222222222222");
            ios["ownerGeneration"]=json!(if reused_generation{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}else{"cccccccccccccccccccccccccccccccc"});
            ios["context"]["platform"]=json!("ios");ios["result"]["context"]=ios["context"].clone();
            ios["result"]["checks"]=json!([{"id":"developer-selection"},tool()["result"]["checks"][1],{"id":"xcode"}]);
            let admitted=second.tools_status(json!({"schemaVersion":1,"statusRevision":4,"active":null,"lastTerminal":ios}),true);
            assert_eq!(admitted.is_ok(),!reused_generation);assert!(!second.complete());
        }
        let mut p=Record::new(Case::Offline,Instant::now());p.dirty=true;
        let mut request=json!({"projectId":"public-project","draftRevision":1,"baselineGeneration":1,"savedConfig":{"bytes":CONFIG.len(),"sha256":digest(CONFIG)}});
        request["savedConfig"]["bytes"]=json!(CONFIG.len()+1);
        assert!(p.prepare_request(&request,Some(Step::Prepare),"public-project").is_err());
        request["savedConfig"]["bytes"]=json!(CONFIG.len());
        p.prepare_request(&request,Some(Step::Prepare),"public-project").unwrap();
        p.offline_status(status(prepared(),1),Some("prepare")).unwrap();
        let start=json!({"operationId":prepared()["operationId"],"ownerGeneration":prepared()["ownerGeneration"],"consentVersion":offline::CONSENT});
        assert!(p.start_request(&start,Some(Step::Run)).is_err());assert!(!p.start.observed);
        p.acknowledged=true;p.start_request(&start,Some(Step::Run)).unwrap();
        let mut running=terminal();running["phase"]=json!("running");running["result"]=Value::Null;
        p.offline_status(status(running,2),Some("start")).unwrap();assert!(p.waiting(Step::OfflineWait));
        p.offline_status(status(terminal(),3),None).unwrap();assert!(!p.waiting(Step::OfflineWait));assert!(!p.complete());
        let mut other=terminal();other["ownerGeneration"]=json!("cccccccccccccccccccccccccccccccc");
        assert!(p.offline_status(status(other,4),None).is_err());
    }
    #[test]
    fn complete_report_never_promotes_readiness(){
        assert!(tool_final(&tool()));assert!(offline_final(&terminal()));
        for (field,value) in [("phase",json!("checking")),("finality",json!("pending")),("outcome",json!("failed"))]{let mut p=tool();p[field]=value;assert!(!tool_final(&p));}
        let mut no_version=tool();no_version["result"]["checks"][1]["version"]=Value::Null;assert!(!tool_final(&no_version));
        for (field,value) in [("phase",json!("running")),("outcome",json!("unknown")),("intentUsable",json!(true))]{let mut p=terminal();p[field]=value;assert!(!offline_final(&p));}
        let mut all_pass=terminal();all_pass["result"]["findings"][1]["status"]=json!("PASS");assert!(!offline_final(&all_pass));
        let mut dirty_identity=terminal();dirty_identity["result"]["usedConfig"]["sha256"]=json!("0".repeat(64));assert!(!offline_final(&dirty_identity));
        let p=terminal();assert_eq!(p["result"]["findings"][1]["status"],"MISSING");
        assert_eq!(LIMITATIONS[6],"release-readiness-not-assessed");assert_eq!(IDS_ANDROID.len(),4);assert_eq!(IDS_IOS.len(),3);
        let mut record=Record::new(Case::Offline,Instant::now());assert!(record.readback().is_err());assert!(!record.complete());
        assert!(offline_render(&p).is_some());
    }
}

const TOOL_LABELS: &[(&str,&str)] = &[
    ("developer-selection","macOS developer selection"),
    ("git","Git version"),
    ("java","Java runtime version"),
    ("javac","Java compiler version"),
    ("xcode","Xcode version and build"),
];

const TOOL_REASONS: &[(&str,&str)] = &[
    ("invalid-draft","Invalid configuration draft"),
    ("platform-disabled","Target disabled in the draft"),
    ("host-mismatch","Host does not support this target"),
    ("unsupported-host","Unsupported host profile"),
    ("missing-in-supported-lookup","Not found in the supported lookup"),
    ("unsupported-installation","Installation outside the supported policy"),
    ("unselected-installation","No unambiguous supported installation selected"),
    ("full-xcode-not-selected","Full Xcode is not selected"),
    ("stopped","Not run before STOP"),
    ("command-incomplete","Command did not complete"),
    ("binding-changed","Admitted installation changed"),
    ("cancelled","Cancellation observed"),
    ("timed-out","Deadline observed"),
    ("observed","Version / selection observed"),
    ("nonzero-exit","Complete command returned a nonzero exit"),
    ("version-unrecognized","Complete output did not match the version format"),
    ("selection-unrecognized","Complete output did not match the selection format"),
];

const FINDING_TEXT: &[(&str,&str)] = &[
    ("version-source","Saved release-version source policy."),
    ("platform-selection","Saved target-platform selection."),
    ("android-module","Android module configuration."),
    ("android-gradle-wrapper","Android Gradle wrapper policy."),
    ("android-debug-identity","Android debug/release identity policy."),
    ("workspace-private-output","Private workspace output policy."),
    ("android-artifact","Android artifact policy; artifact validation was not requested."),
    ("preflight-early-exit","Core early-exit or remaining-check policy."),
    ("configuration-policy","Saved configuration policy."),
    ("metadata-policy","Project metadata policy."),
    ("configured-project-check","Configured project check."),
    ("core-lifecycle","Core lifecycle finding."),
    ("other-core-finding","Other core finding; its exact core status is preserved."),
];

const LIMIT_TEXT: &[(&str,&str)] = &[
    ("saved-inputs-not-atomic","Saved inputs were not an atomic checkout. Script bodies, version sources and metadata may change externally; no filesystem watcher is promised."),
    ("project-code-effects-possible","Configured project code can modify files, run programs, build things and read your account’s files."),
    ("not-network-isolated","Offline selects the core checking mode. It is not network isolation or a sandbox."),
    ("core-builds-disabled","Core-managed builds were disabled; configured checks can still perform their own builds."),
    ("artifact-validation-not-requested","Artifact validation was not requested by the toolkit."),
    ("toolkit-signing-credentials-store-not-requested","The toolkit did not request signing, credential loading or Store access. Arbitrary project code is not constrained by that selection."),
    ("release-readiness-not-assessed","Release readiness was not assessed. A returned report is not a release candidate or publication authority."),
];
