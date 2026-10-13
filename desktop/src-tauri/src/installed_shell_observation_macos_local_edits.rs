//! Three fixed, installed UI journeys. These observations never grant writer
//! authority: the normal EditOwner and its actual returned originals do that.
//! The single external stale append is deliberately separate from product Apply.
use super::*;
use crate::{github_workflow_edit_protocol as workflow, metadata_text_edit_protocol as metadata,
    release_version_edit_protocol as version,
    edit_owner::{InstalledWorkflowFinality, InstalledMetadataFinality, InstalledVersionFinality}};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Case { Metadata, Version, Workflow }
impl Case {
    pub(crate) fn name(self) -> &'static str { match self { Self::Metadata => "local-metadata-text", Self::Version => "local-release-version", Self::Workflow => "local-github-apply" } }
    pub(crate) fn parse(name: &str) -> Option<Self> { [Self::Metadata,Self::Version,Self::Workflow].into_iter().find(|c| c.name()==name) }
    pub(crate) fn seconds(self) -> u64 { match self { Self::Metadata=>120,Self::Version=>90,Self::Workflow=>180 } }
    fn domain(self) -> &'static str { match self { Self::Metadata=>metadata::DOMAIN,Self::Version=>version::DOMAIN,Self::Workflow=>workflow::DOMAIN } }
    fn sessions(self) -> usize { match self { Self::Metadata=>2,Self::Version=>1,Self::Workflow=>3 } }
}
pub(super) const NAMES: [&str;3] = ["local-metadata-text","local-release-version","local-github-apply"];
const REPOSITORY: &str = "example/toolkit";
const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESOURCE: &str = "6fa1f3b7dd1907f56af44ccf050458626d702ec0a06e5578a7416986c46ad29a";
const WORKFLOWS: [(&str,&str,usize);4] = [
    ("preflight",".github/workflows/mobile-preflight.yml",1479),
    ("candidate",".github/workflows/mobile-candidate.yml",2303),
    ("external-testing",".github/workflows/mobile-external-testing.yml",3079),
    ("production-submit",".github/workflows/mobile-production-submit.yml",3816)];
const STALE: &[u8] = b"# MRK local workflow original changed\n";
const VERSION_BEFORE: &[u8] = b"# Public local edit fixture\n  VERSION_NAME = 1.2.3  \nBUILD_NUMBER=7\nUNRELATED = keep-this-value\n";
const VERSION_AFTER: &[u8] = b"# Public local edit fixture\n  VERSION_NAME = 2.3.4  \nBUILD_NUMBER=8\nUNRELATED = keep-this-value\n";
const ANDROID: [(&str,Option<&str>,&str);3] = [
    ("title.txt",Some("Public title"),"Public title"),
    ("short_description.txt",Some("Old summary"),"Public summary"),
    ("full_description.txt",None,"Public description")];
const IOS: [(&str,Option<&str>,&str);5] = [
    ("description.txt",Some("Old iOS description"),"Public iOS description"),
    ("keywords.txt",Some("public,example"),"public,example"),
    ("privacy_url.txt",Some("https://example.com/privacy"),"https://example.com/privacy"),
    ("support_url.txt",Some("https://example.com/support"),"https://example.com/support"),
    ("release_notes.txt",None,"Public release notes")];
fn fields(round: usize) -> Option<&'static [(&'static str,Option<&'static str>,&'static str)]> {
    match round {0=>Some(&ANDROID),1=>Some(&IOS),_=>None}
}
fn platform(round: usize) -> Option<&'static str> { match round {0=>Some("android"),1=>Some("ios"),_=>None} }
fn text_path(round: usize, id: &str) -> Option<String> { Some(format!("release/store/{}/en-US/{id}",platform(round)?)) }
fn text_values(round: usize) -> Option<Value> { Some(json!(fields(round)?.iter().map(|(id,_,text)|json!({"id":id,"text":text})).collect::<Vec<_>>())) }
pub(crate) fn config(case: Case) -> Result<Vec<u8>,()> {
    if case != Case::Metadata { return Ok(CONFIG.to_vec()); }
    let mut value = crate::protocol::strict_json(CONFIG).map_err(|_|())?;
    value["ios"] = json!({"archiveConfiguration":"Release","bundleId":APP_ID,"enabled":true,"identityStatus":"unverified",
        "project":"ios/MRKObserved.xcodeproj","scheme":"MRKObserved","symbols":{"policy":"retain"}});
    value["metadata"]["iosLocales"] = json!(["en-US"]);
    let mut bytes=serde_json::to_vec_pretty(&value).map_err(|_|())?; bytes.push(b'\n'); Ok(bytes)
}

// Closed roster derived only from the case and already checked public proposal.
// It is never a directory scanner or a renderer-selected path.
// Existing Aqua main fixes inherited umask 077 before run_cases. Core requests
// 0644 for newly created files; the resulting mode here must therefore be 0600.
fn files(case: Case, completed: usize, proposal: Option<&Value>, stale: bool) -> Result<BTreeMap<String,(Vec<u8>,u32)>,()> {
    if completed>case.sessions() || stale && (case!=Case::Workflow || completed<2) {return Err(());}
    let mut rows=BTreeMap::from([
        (".gitignore".into(),(super::Fixture::ignore_bytes(true,false),0o600)),
        ("app/build.gradle.kts".into(),(SOURCE.to_vec(),0o600)),
        ("keep.txt".into(),(KEEP.to_vec(),0o600)),
        ("release/mobile-release.json".into(),(config(case)?,0o600)),
        ("version.properties".into(),((if case==Case::Version { if completed==0 {VERSION_BEFORE}else{VERSION_AFTER} }else{VERSION}).to_vec(),0o600)),
    ]);
    if case==Case::Metadata {
        for round in 0..2 { for (id,before,after) in fields(round).ok_or(())? {
            let text=if completed>round {Some(*after)}else{*before};
            if let Some(text)=text {rows.insert(text_path(round,id).ok_or(())?,(text.as_bytes().to_vec(),0o600));}
        }}
        rows.insert("release/store/keep.txt".into(),(KEEP.to_vec(),0o600));
    }
    if case==Case::Workflow {
        rows.insert(".github/workflows/unrelated.yml".into(),(b"# Retained unrelated workflow; no dispatch\n".to_vec(),0o600));
        if completed>=2 {let proposal=proposal.ok_or(())?;
            for (i,(_,path,size)) in WORKFLOWS.iter().enumerate() {
                let body=proposal[i]["content"].as_str().ok_or(())?;
                if body.len()!=*size {return Err(());} let mut bytes=body.as_bytes().to_vec();
                if stale && i==0 {bytes.extend_from_slice(STALE);}
                rows.insert((*path).into(),(bytes,0o600));
            }
        }
    }
    if rows.len()>32 || rows.values().map(|(b,_)|b.len()).sum::<usize>()>1024*1024 {return Err(());} Ok(rows)
}
fn directories(rows: &BTreeMap<String,(Vec<u8>,u32)>, case: Case) -> Result<BTreeMap<String,Vec<String>>,()> {
    let mut names=BTreeMap::<String,Vec<String>>::new(); names.insert(".".into(),Vec::new());
    let mut leaves:Vec<String>=rows.keys().cloned().collect();
    if case==Case::Metadata {leaves.extend(["release/store/android/en-US/.not-a-file","release/store/ios/en-US/.not-a-file"].map(str::to_owned));}
    for path in leaves {let parts:Vec<_>=path.split('/').collect();
        for i in 0..parts.len() {let parent=if i==0 {".".into()}else{parts[..i].join("/")};
            let entry=parts[i].to_owned();let children=names.entry(parent).or_default();
            if entry!=".not-a-file" && !children.contains(&entry) {children.push(entry);}
        }
    }
    for row in names.values_mut(){row.sort();if row.len()>16{return Err(());}}
    if names.len()>24{return Err(());} Ok(names)
}
pub(super) struct Fixture { case:Case, completed:usize, stale:bool, files:BTreeMap<String,FileFact>, dirs:BTreeMap<String,[u64;6]>, proposal:Option<Value> }
impl Fixture {
    pub(crate) fn capture(root:&Path,uid:u32,case:Case)->Result<Self,()> {
        let roster=files(case,0,None,false)?; let mut facts=BTreeMap::new();let mut dirs=BTreeMap::new();
        for (path,(bytes,mode)) in &roster {facts.insert(path.clone(),file_fact_mode(&root.join(path),bytes,uid,*mode)?);}
        for (path,entries) in directories(&roster,case)? {
            let entries:Vec<_>=entries.iter().map(String::as_str).collect();
            dirs.insert(path.clone(),directory(&root.join(path),uid,0o700,&entries)?);
        }
        Ok(Self{case,completed:0,stale:false,files:facts,dirs,proposal:None})
    }
    pub(super) fn dir(&self,path:&str)->Option<[u64;6]>{self.dirs.get(path).copied()}
    pub(super) fn file(&self,path:&str)->Option<FileFact>{self.files.get(path).cloned()}
    pub(crate) fn root_identity(&self)->Result<[u64;6],()>{self.dirs.get(".").copied().ok_or(())}
    pub(crate) fn ignore(&self)->Result<FileFact,()>{self.files.get(".gitignore").cloned().ok_or(())}
    pub(crate) fn verify(&self,root:&Path,uid:u32)->Result<(),()> {
        let expected=files(self.case,self.completed,self.proposal.as_ref(),self.stale)?;
        if expected.len()!=self.files.len(){return Err(());}
        for (path,(bytes,mode)) in expected.iter(){if self.files.get(path)!=Some(&file_fact_mode(&root.join(path),bytes,uid,*mode)?){return Err(());}}
        let dirs=directories(&expected,self.case)?;if dirs.len()!=self.dirs.len(){return Err(());}
        for (path,entries) in dirs {let refs:Vec<_>=entries.iter().map(String::as_str).collect();
            if self.dirs.get(&path)!=Some(&directory(&root.join(path),uid,0o700,&refs)?){return Err(());}}
        Ok(())
    }
    // Only after the *actual* same original has returned and its final getter
    // has joined every resource. Frozen unchanged originals may not be replaced.
    pub(super) fn after(&mut self,root:&Path,uid:u32,index:usize,proposal:Option<&Value>)->Result<(),()> {
        if index!=self.completed || index>=self.case.sessions(){return Err(());}
        let before=files(self.case,index,self.proposal.as_ref(),self.stale)?;
        let after=files(self.case,index+1,proposal.or(self.proposal.as_ref()),self.stale)?;
        let mut facts=BTreeMap::new();
        for (path,(bytes,mode)) in &after {let fact=file_fact_mode(&root.join(path),bytes,uid,*mode)?;
            if before.get(path).is_some_and(|(old,m)|old==bytes&&m==mode) && self.files.get(path)!=Some(&fact){return Err(());} facts.insert(path.clone(),fact);
        }
        for (path,entries) in directories(&after,self.case)? {let refs:Vec<_>=entries.iter().map(String::as_str).collect();
            if self.dirs.get(&path)!=Some(&directory(&root.join(path),uid,0o700,&refs)?){return Err(());}}
        self.files=facts;self.completed=index+1;if let Some(p)=proposal{self.proposal=Some(p.clone());}self.verify(root,uid)
    }
    pub(super) fn append_stale(&mut self,root:&Path,uid:u32,end:Instant,failed:&AtomicBool)->Result<(),()> {
        let current=||!failed.load(Ordering::Acquire)&&Instant::now()<end;
        if self.case!=Case::Workflow || self.completed!=2 || self.stale || !current(){return Err(());}self.verify(root,uid)?;
        let path=root.join(WORKFLOWS[0].1);let original=self.files.get(WORKFLOWS[0].1).ok_or(())?.clone();
        let before=self.proposal.as_ref().and_then(|p|p[0]["content"].as_str()).ok_or(())?.as_bytes();
        let mut file=OpenOptions::new().read(true).append(true).custom_flags(nix::libc::O_NOFOLLOW|nix::libc::O_CLOEXEC).open(&path).map_err(|_|())?;
        let result=(||{
            if identity(&file.metadata().map_err(|_|())?)?!=original.identity || identity(&std::fs::symlink_metadata(&path).map_err(|_|())?)?!=original.identity
                || !current(){return Err(());}
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_|())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_|())?;
            let mut data=Vec::new();std::io::Read::by_ref(&mut file).take((before.len()+1) as u64).read_to_end(&mut data).map_err(|_|())?;
            if data!=before || identity(&file.metadata().map_err(|_|())?)?!=original.identity || !current(){return Err(());}
            if file.write(STALE).map_err(|_|())?!=STALE.len(){return Err(());}file.sync_all().map_err(|_|())?;
            let held=identity(&file.metadata().map_err(|_|())?)?;let named=identity(&std::fs::symlink_metadata(&path).map_err(|_|())?)?;
            if held!=named || held[..6]!=original.identity[..6] || held[6]!=(before.len()+STALE.len()) as u64 || !current(){return Err(());}Ok(held)
        })();
        let closed=nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
        let held=result?;if !closed || !current(){return Err(());}let mut bytes=before.to_vec();bytes.extend_from_slice(STALE);
        let readback=file_fact_mode(&path,&bytes,uid,0o600)?;
        if readback.identity!=held || !current(){return Err(());}self.files.insert(WORKFLOWS[0].1.into(),readback);self.stale=true;self.verify(root,uid)
    }
    fn report(&self)->Value {json!({"files":self.files.len(),"directories":self.dirs.len(),"completedOriginals":self.completed,
        "staleAppendReturnedAndClosed":self.stale,"sha256":self.files.iter().map(|(p,f)|(p.clone(),f.sha256.clone())).collect::<BTreeMap<_,_>>()})}
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Step {
    Navigate, Context(u8), Loaded(u8), Load(u8), Fill(u8,u8), Inputs(u8), Validate(u8), Validated(u8),
    Open(u8), Opened(u8), Name, Build, Prepare(u8), OpenText(u8), Review(u8),
    Confirm(u8), Confirmation(u8), Check(u8), Checked(u8), Type(u8), Typed(u8), Apply(u8), Result(u8),
    CloseReview, Closed, Refresh(u8), Readback(u8), Repository, Pin, Propose, Proposal, Mutate, Done,
}
fn order(phase:&Value)->Option<u8>{["opening","editing","preparing","reviewing","applying","finalizing","final"].iter().position(|s|phase==*s).map(|i|i as u8)}
fn tok(value:&Value)->bool{value.as_str().is_some_and(edit::token)}
fn same(a:&Value,b:&Value)->bool{["domain","projectId","sessionId","ownerGeneration"].into_iter().all(|k|a[k]==b[k])}
fn live(p:&Value)->bool{p["phase"]=="reviewing" && p["reviewRemainingMs"].as_u64().is_some_and(|n|n>0)
    && p["applySubmitted"]==false && p["coreOutcome"].is_null() && p["nativeReason"]=="none" && p["nativeFinality"]=="pending" && p["lateSettled"]==false}
// Typed original evidence stays retained. Serialised renderer DATA cannot make
// any variant, and no `Final` badge substitutes for this original getter.
enum Finality { Workflow(InstalledWorkflowFinality), Metadata(InstalledMetadataFinality), Version(InstalledVersionFinality) }
macro_rules! original_matches {($f:expr,$p:expr,$domain:expr)=>{{let f=$f;let p=$p;
    p["domain"]==$domain && p["sessionId"]==f.session_id && p["projectId"]==f.project_id && p["ownerGeneration"]==f.owner_generation
    && f.writer_frames==(if p["applySubmitted"]==true{3}else{2}) && f.stdout_frames==3
    && f.inspection_joined&&f.acquisition_joined&&f.child_waited_success&&f.stdin_closed&&f.stdout_eof_closed&&f.stderr_eof_closed
    && f.io_joined&&f.driver_joined&&f.watchdog_joined&&f.manager_joined&&f.runtime_ledger_settled&&f.runtime_settlement_joined
}}}
impl Finality {fn matches(&self,p:&Value)->bool{match self{Self::Workflow(f)=>original_matches!(f,p,workflow::DOMAIN),Self::Metadata(f)=>original_matches!(f,p,metadata::DOMAIN),Self::Version(f)=>original_matches!(f,p,version::DOMAIN)}}}
struct Session { projection:Value, first_revision:u64, open_returned:bool, prepare:Option<Value>, prepare_returned:bool,
    review_visible:bool, acknowledged:bool, apply_requested:bool, apply_returned:bool, close_requested:bool,
    confirmation:u8, config_blocked:bool, finality:Option<Finality>, readback:bool, visible:bool }
impl Session {fn complete(&self)->bool{self.open_returned&&self.prepare.is_some()&&self.prepare_returned&&self.review_visible
    && self.config_blocked&&self.visible&&self.readback&&self.finality.as_ref().is_some_and(|f|f.matches(&self.projection))
    && (if self.close_requested{!self.apply_requested&&!self.apply_returned&&!self.acknowledged}else{self.apply_requested&&self.apply_returned&&self.acknowledged})}}
pub(super) struct Record {case:Case, generation:Option<String>,revision:u64,capability:bool,
    sessions:Vec<Session>,open_pending:Option<(usize,u64,String)>,passive_pending:Option<usize>,
    observations:Vec<Value>,validation_pending:Option<usize>,validations:Vec<Value>,proposal_pending:bool,proposal:Option<Value>,
    config_blocked:bool, selection_visible:bool}
impl Record {
    pub(super) fn proposal(&self)->Option<&Value>{self.proposal.as_ref()}
    pub(crate) fn new(case:Case)->Self{Self{case,generation:None,revision:0,capability:false,sessions:Vec::with_capacity(3),open_pending:None,
        passive_pending:None,observations:Vec::new(),validation_pending:None,validations:Vec::new(),proposal_pending:false,proposal:None,
        config_blocked:false,selection_visible:false}}
    fn current(&self)->Result<&Session,()>{self.sessions.last().ok_or(())}
    fn current_mut(&mut self)->Result<&mut Session,()>{self.sessions.last_mut().ok_or(())}
    fn open_request(&mut self,index:usize,project:&str)->Result<(),()>{
        if index>=self.case.sessions()||self.sessions.len()!=index||self.open_pending.is_some()||!self.capability||self.generation.is_none()
            ||self.sessions.iter().any(|s|!s.complete()){return Err(());}self.open_pending=Some((index,self.revision,project.into()));Ok(())
    }
    fn status(&mut self,value:Value,returned:Option<&str>,facts:Option<Finality>)->Result<(),()>{
        if value["schemaVersion"]!=1 || value["domain"]!=self.case.domain() || !tok(&value["windowGeneration"]){return Err(());}
        let generation=value["windowGeneration"].as_str().ok_or(())?;
        if self.generation.as_deref().is_some_and(|g|g!=generation){return Err(());}self.generation=Some(generation.into());
        let rev=value["statusRevision"].as_u64().filter(|n|*n<=u32::MAX as u64).ok_or(())?;
        if value["capability"]==json!({"available":false,"reason":"shutdown"})
            &&value["active"].is_null()&&self.sessions.len()==self.case.sessions()&&self.sessions.iter().all(Session::complete)
            &&self.sessions.last().is_some_and(|s|value["lastTerminal"]==s.projection){return Ok(());}
        if value["capability"]!=json!({"available":true,"reason":"available"}) {return Err(());}self.capability=true;
        // A delayed broadcast from the same generation may not replace or
        // authenticate a newer original. Replies still undergo their own checks.
        if returned.is_none()&&rev<self.revision{return Ok(());}
        let active=&value["active"];let last=&value["lastTerminal"];
        if !active.is_null()&&!last.is_null()&&!self.sessions.iter().any(|s|s.projection==*last&&s.finality.is_some()){return Err(());}
        let p=if active.is_null(){last}else{active};
        if p.is_null(){if !self.sessions.is_empty()||self.open_pending.is_some()||returned.is_some(){return Err(());}self.revision=self.revision.max(rev);return Ok(());}
        if p["domain"]!=self.case.domain()||p["ownerGeneration"]!=generation||!tok(&p["sessionId"])||order(&p["phase"]).is_none()
            ||p["lateSettled"]!=false||!p["conflict"].is_null()||!p["recovery"].is_null(){return Err(());}
        let existing=self.sessions.last().is_some_and(|s|same(&s.projection,p));
        if !existing {
            let (index,after,project)=self.open_pending.as_ref().ok_or(())?;
            if *index!=self.sessions.len()||rev<=*after||p["projectId"]!=*project||self.sessions.iter().any(|s|s.projection["sessionId"]==p["sessionId"])
                || !matches!(p["phase"].as_str(),Some("opening"|"editing")) ||p["applySubmitted"]!=false||!p["prepared"].is_null()
                ||p["nativeFinality"]!="pending"||p["nativeReason"]!="none"||!p["coreOutcome"].is_null()
                ||(p["phase"]=="opening")!=p["checkout"].is_null(){return Err(());}
            self.sessions.push(Session{projection:p.clone(),first_revision:rev,open_returned:false,prepare:None,prepare_returned:false,
                review_visible:false,acknowledged:false,apply_requested:false,apply_returned:false,close_requested:false,confirmation:0,config_blocked:false,
                finality:None,readback:false,visible:false});
        }
        let index=self.sessions.len()-1;
        if returned==Some("open") {
            let pending_index=self.open_pending.as_ref().ok_or(())?.0;
            let s=self.current_mut()?;
            if s.open_returned||p["phase"]!="opening"||!p["checkout"].is_null()||rev>s.first_revision||!same(&s.projection,p)||pending_index!=index{return Err(());}
            s.open_returned=true;self.open_pending=None;
        }
        if returned==Some("prepare") {let s=self.current_mut()?;
            if s.prepare.is_none()||s.prepare_returned||p["phase"]!="preparing"||p["applySubmitted"]!=false||!p["prepared"].is_null(){return Err(());}s.prepare_returned=true;}
        if returned==Some("apply") {let s=self.current_mut()?;
            if !s.apply_requested||s.apply_returned||p["phase"]!="applying"||p["applySubmitted"]!=true{return Err(());}s.apply_returned=true;}
        if returned==Some("close") {return Err(());} // Only workflow Close is selected; it has no result hook.
        if rev<self.revision {return Ok(());} // Original replies checked above; never regress an observed newer phase.
        let case=self.case;let old_revision=self.revision;let s=self.current_mut()?;
        if !same(&s.projection,p)||order(&p["phase"])<order(&s.projection["phase"])
            ||s.projection["applySubmitted"]==true&&p["applySubmitted"]!=true
            ||!s.projection["checkout"].is_null()&&s.projection["checkout"]!=p["checkout"]
            ||!s.projection["prepared"].is_null()&&s.projection["prepared"]!=p["prepared"]{return Err(());}
        if rev==old_revision {let mut comparison=p.clone();comparison["reviewRemainingMs"]=s.projection["reviewRemainingMs"].clone();
            if comparison!=s.projection||p["reviewRemainingMs"].as_u64()>s.projection["reviewRemainingMs"].as_u64(){return Err(());}}
        if !p["prepared"].is_null(){if s.prepare.is_none(){return Err(());} }
        let close=case==Case::Workflow&&index==0;let stale=case==Case::Workflow&&index==2;
        let outcome=json!({"effect":if close||stale{"not_started"}else{"committed"},"journal":if close||stale{"not_created"}else{"clean"},"resources":"settled","reason":if stale{"stale_revision"}else if close{"cancelled"}else{"none"}});
        if p["applySubmitted"]!= (s.apply_requested&&order(&p["phase"])>=Some(4))
            ||p["nativeReason"]!=if close&&s.close_requested&&order(&p["phase"])>=Some(5){"discarded"}else{"none"}
            ||!p["coreOutcome"].is_null()&&(order(&p["phase"])<Some(5)||p["coreOutcome"]!=outcome){return Err(());}
        if p["phase"]=="final" {
            if p["nativeFinality"]!="settled"||p["coreOutcome"]!=outcome||close!=s.close_requested||!close&&!s.apply_requested{return Err(());}
            if s.finality.is_none(){let f=facts.ok_or(())?;if !f.matches(p){return Err(());}s.finality=Some(f);}
        }else if p["nativeFinality"]!="pending"{return Err(());}
        s.projection=p.clone();self.revision=rev;Ok(())
    }
    fn prepare_request(&mut self,body:Value,base:&Value)->Result<(),()>{
        let index=self.sessions.len().checked_sub(1).ok_or(())?;let case=self.case;
        let pending=self.open_pending.as_ref().map(|p|p.0)==Some(index);
        self.check_checkout(index,&self.current()?.projection)?;
        let s=self.current_mut()?;let p=&s.projection;
        if (!s.open_returned&&!pending)||s.prepare.is_some()||p["phase"]!="editing"||p["checkout"].is_null()
            ||body["sessionId"]!=p["sessionId"]||body["revision"]!=p["checkout"]["revision"]||!tok(&body["revision"])
            ||!body["draftRevision"].as_u64().is_some_and(|n|n<u32::MAX as u64)||!body["baselineGeneration"].as_u64().is_some_and(|n|n<u32::MAX as u64){return Err(());}
        match case {
            Case::Workflow=>{if body["draft"]!=*base||body["toolingRepository"]!=REPOSITORY||body["toolingSha"]!=PIN{return Err(());}},
            Case::Metadata=>{if body["expectedBaseline"]!=p["checkout"]["baseline"]||body["fields"]!=text_values(index).ok_or(())?{return Err(());}},
            Case::Version=>{if body["expectedBaseline"]!=p["checkout"]["baseline"]||body["intent"]!="edit"||body["values"]!=json!({"name":"2.3.4","build":"8"}){return Err(());}},
        }
        s.prepare=Some(body);Ok(())
    }
    fn apply_request(&mut self,id:&str,token:&str)->Result<(),()>{let s=self.current_mut()?;
        if !live(&s.projection)||!s.config_blocked||!s.prepare_returned||!s.review_visible||!s.acknowledged||s.apply_requested||s.close_requested
            ||s.projection["sessionId"]!=id||s.projection["prepared"]["planToken"]!=token||!edit::token(token){return Err(());}s.apply_requested=true;Ok(())}
    fn close_request(&mut self)->Result<(),()>{if self.case!=Case::Workflow||self.sessions.len()!=1{return Err(());}let s=self.current_mut()?;
        if !live(&s.projection)||!s.config_blocked||!s.prepare_returned||!s.review_visible||s.apply_requested||s.close_requested{return Err(());}s.close_requested=true;Ok(())}
}
fn content(text:&str,size:&str)->Value {let mut value=json!({"text":text,"sha256":digest(text.as_bytes())});value[size]=json!(text.len());value}
fn baseline(round:usize,saved:bool)->Result<Value,()> {
    let config=config(Case::Metadata)?;let rows=fields(round).ok_or(())?.iter().map(|(id,before,after)|{
        let text=if saved {Some(*after)}else{*before};match text{Some(text)=>json!({"id":id,"state":"present","byteLength":text.len(),"sha256":digest(text.as_bytes())}),None=>json!({"id":id,"state":"absent"})}
    }).collect::<Vec<_>>();Ok(json!({"config":{"byteLength":config.len(),"sha256":digest(&config)},"fields":rows}))
}
fn expected_metadata(round:usize)->Result<Value,()> {Ok(json!(fields(round).ok_or(())?.iter().map(|(id,before,after)|{
    let old=match before{Some(text)=>{let mut v=content(text,"byteLength");v["state"]=json!("present");v},None=>json!({"state":"absent"})};
    json!({"id":id,"path":text_path(round,id),"action":if before==&Some(*after){"preserve"}else if before.is_some(){"replace"}else{"create"},
        "before":old,"after":content(after,"byteLength"),"lineEndingsChanged":false})
}).collect::<Vec<_>>()))}
fn metadata_display(round:usize,edited:bool,validated:bool,saved:bool)->Result<Value,()> {Ok(json!({
    "context":format!("{} / en-US",platform(round).ok_or(())?),"badge":"Selected text only","fields":fields(round).ok_or(())?.iter().map(|(id,before,after)|{
        let text=if edited{*after}else{before.unwrap_or("")};let changed=before!=&Some(*after);
        json!({"id":id,"path":text_path(round,id),"text":text,"badges":["Required",if saved{"Saved baseline"}else if edited&&changed{"Unsaved text"}else if before.is_none(){"Missing · observed"}else{"Observed original"}],"invalid":if validated&&!saved{Some("false")}else{None}})
    }).collect::<Vec<_>>(),"loadLabel":"Refresh text","loadAvailable":true,"validateAvailable":true,"reviewAvailable":validated&&!saved,
    "validation":if saved{Some("Stale validation")}else if validated{Some("Format-valid selected text")}else{None}}))}
fn version_view()->Value {
    let before=std::str::from_utf8(VERSION_BEFORE).unwrap_or("");let after=std::str::from_utf8(VERSION_AFTER).unwrap_or("");
    let mut old=content(before,"bytes");old["state"]=json!("present");
    json!({"schemaVersion":1,"source":"version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER","iosEnabled":false,
        "intent":"edit","values":{"name":"2.3.4","build":"8"},"file":{"path":"version.properties","action":"replace","before":old,
        "after":content(after,"bytes"),"requestedMode":384,"preserveMode":true},"createDirectories":[],
        "lineEndings":{"before":["lf"],"after":["lf"],"finalNewlineBefore":true,"finalNewlineAfter":true,"preserved":true},
        "validation":{"valid":true,"state":"format-valid","issues":[]}})
}
impl Record {
    fn check_checkout(&self,index:usize,p:&Value)->Result<(),()> {
        let c=&p["checkout"];if c.is_null(){return if p["phase"]=="opening"{Ok(())}else{Err(())};}
        if !tok(&c["revision"])||self.sessions.iter().take(index).any(|s|s.projection["checkout"]["revision"]==c["revision"]){return Err(());}
        match self.case {
            Case::Metadata=>if p["platform"]!=platform(index).ok_or(())?||p["locale"]!="en-US"||c["metadataRoot"]!="release/store"||c["baseline"]!=baseline(index,false)?{return Err(());},
            Case::Version=>if c["source"]!="version.properties"||c["nameKey"]!="VERSION_NAME"||c["buildKey"]!="BUILD_NUMBER"||c["iosEnabled"]!=false
                ||c["values"]!=json!({"name":"1.2.3","build":"7"})||c["baseline"]!=json!({"savedConfig":{"bytes":CONFIG.len(),"sha256":digest(CONFIG)},"savedVersion":{"state":"present","bytes":VERSION_BEFORE.len(),"sha256":digest(VERSION_BEFORE)}}){return Err(());},
            Case::Workflow=>{let rows:Vec<_>=WORKFLOWS.iter().enumerate().map(|(i,(id,_,size))|if index<2{json!({"id":id,"state":"absent"})}
                else{json!({"id":id,"state":"present","byteLength":size,"sha256":self.proposal.as_ref().map(|p|p[i]["sha256"].clone())})}).collect();
                if c["observed"]!=json!(rows){return Err(());}}
        }Ok(())
    }
    fn review(&self,index:usize)->Result<Value,()> {
        let s=self.sessions.get(index).ok_or(())?;let p=&s.projection;let submitted=s.prepare.as_ref().ok_or(())?;let prepared=&p["prepared"];
        if !s.open_returned||!s.prepare_returned||!live(p)||!tok(&prepared["planToken"])||prepared["revision"]!=p["checkout"]["revision"]
            ||prepared["draftRevision"]!=submitted["draftRevision"]||prepared["baselineGeneration"]!=submitted["baselineGeneration"]{return Err(());}
        if self.sessions.iter().take(index).any(|s|s.projection["prepared"]["planToken"]==prepared["planToken"]){return Err(());}
        self.check_checkout(index,p)?;let view=&prepared["view"];
        match self.case {
            Case::Metadata=>{let expected=expected_metadata(index)?;
                if view["schemaVersion"]!=1||view["platform"]!=platform(index).ok_or(())?||view["locale"]!="en-US"||view["metadataRoot"]!="release/store"
                    ||view["createDirectories"]!=json!([])||view["files"]!=expected||self.validations.get(index)!=Some(&view["validation"]){return Err(());}Ok(expected)},
            Case::Version=>{let expected=version_view();if view!=&expected{return Err(());}Ok(json!({"before":view["file"]["before"],"after":view["file"]["after"]}))},
            Case::Workflow=>{
                let proposal=self.proposal.as_ref().ok_or(())?;let mut inventory=Vec::new();let mut texts=Vec::new();let mut native=Vec::new();
                for (i,(id,path,size)) in WORKFLOWS.iter().enumerate(){let generated=&proposal[i];let body=generated["content"].as_str().ok_or(())?;
                    let preserved=index==2;let observed=if preserved{json!({"state":"present","byteLength":size,"sha256":generated["sha256"]})}else{json!({"state":"absent"})};
                    let action=if preserved{"preserve"}else{"create"};
                    native.push(json!({"id":id,"path":path,"action":action,"observed":observed,"generated":{"content":body,"byteLength":size,"sha256":generated["sha256"]}}));
                    inventory.push(json!({"path":path,"action":action,"observed":observed,"generated":{"byteLength":size,"sha256":generated["sha256"]}}));
                    let lines=body.lines().count();let prefix=if preserved{" "}else{"+"};let rendered=body.lines().map(|s|format!("{prefix}{s}\n")).collect::<String>();
                    texts.push(json!({"path":path,"badge":if preserved{"Full unchanged context"}else{"Full added text"},
                        "label":format!("Complete {} for {path}",if preserved{"unchanged generated context"}else{"added diff"}),
                        "content":format!("--- {}\n+++ {path}\n@@ {} +1,{lines} @@\n{rendered}",if preserved{*path}else{"/dev/null"},if preserved{format!("-1,{lines}")}else{"-0,0".into()})}));
                }
                let template=json!({"coreVersion":crate::runtime::CORE_VERSION,"resourceVersion":1,"resourceSha256":RESOURCE});
                let tooling=json!({"repository":REPOSITORY,"sha":PIN,"schemaReference":format!("https://raw.githubusercontent.com/{REPOSITORY}/{PIN}/schemas/project.schema.json"),"state":"format-only"});
                if view!=&json!({"schemaVersion":1,"files":native,"createDirectories":[],"templateSet":template,"tooling":tooling}){return Err(());}
                Ok(json!({"files":inventory,"texts":texts,"basis":if index<2{"Create absent or update canonical callers only"}else{"No file writes are planned"},
                    "facts":[["Toolkit repository",REPOSITORY],["Toolkit commit · format-only",PIN],["Core / resource version",&format!("{} / 1",crate::runtime::CORE_VERSION)],
                        ["Resource identity SHA256",RESOURCE],["Schema reference · informational, not fetched or saved",tooling["schemaReference"].as_str().ok_or(())?]],
                    "note":"Existing ancestors are preserved. New directories use 0755; new files request 0644 subject to inherited umask. Updates retain original permissions. Exact-preserved originals are not rewritten or chmodded.",
                    "caution":"Draft validation was required for this plan, but no configuration save is required or performed. The toolkit ref and template compatibility are not remotely verified. GitHub, credentials, unknown workflow siblings, .gitignore, Git/index state and release operations are outside this plan."}))
            }
        }
    }
    fn passive_request(&mut self,step:Step,body:&Value,project:&str)->Result<(),()> {
        let round=match(step,self.case){(Step::Load(i)|Step::Loaded(i)|Step::Refresh(i)|Step::Readback(i),Case::Metadata)=>usize::from(i),
            (Step::Load(0)|Step::Loaded(0)|Step::Refresh(0)|Step::Readback(0),Case::Version)=>0,_=>return Err(())};
        let slot=round*2+usize::from(matches!(step,Step::Refresh(_)|Step::Readback(_)));
        if self.passive_pending.is_some()||self.observations.len()!=slot||body!=&if self.case==Case::Metadata{json!({"projectId":project,"platform":platform(round).ok_or(())?,"locale":"en-US"})}else{json!({"projectId":project})}{return Err(());}
        self.passive_pending=Some(slot);Ok(())
    }
    fn passive_result(&mut self,value:Value)->Result<(),()> {
        let slot=self.passive_pending.take().ok_or(())?;let round=slot/2;let saved=slot%2==1;
        if self.observations.len()!=slot||!assurance(&value,"static-text")||value["observationScope"]!="single-request-non-atomic"{return Err(());}
        if self.case==Case::Metadata {
            let base=baseline(round,saved)?;let rows=fields(round).ok_or(())?.iter().enumerate().map(|(i,(id,before,after))|{
                let mut row=base["fields"][i].clone();row["path"]=json!(text_path(round,id));
                if let Some(text)=if saved{Some(*after)}else{*before}{row["text"]=json!(text);}row}).collect::<Vec<_>>();
            if value["schemaVersion"]!=1||value["platform"]!=platform(round).ok_or(())?||value["locale"]!="en-US"||value["metadataRoot"]!="release/store"||value["baseline"]!=base||value["fields"]!=json!(rows){return Err(());}
        }else if self.case==Case::Version {
            let bytes=if saved{VERSION_AFTER}else{VERSION_BEFORE};if value["schemaVersion"]!=2||value["source"]!="version.properties"
                ||value["version"]!=json!({"name":if saved{"2.3.4"}else{"1.2.3"},"build":if saved{8}else{7}})
                ||value["savedConfig"]!=json!({"bytes":CONFIG.len(),"sha256":digest(CONFIG)})||value["savedVersion"]!=json!({"bytes":bytes.len(),"sha256":digest(bytes)}){return Err(());}
        }else{return Err(());}self.observations.push(value);Ok(())
    }
    fn validation_result(&mut self,value:Value)->Result<(),()> {
        let round=self.validation_pending.take().ok_or(())?;let rows=value["fields"].as_array().ok_or(())?;
        if self.validations.len()!=round||value["schemaVersion"]!=1||value["platform"]!=platform(round).ok_or(())?||value["valid"]!=true||value["state"]!="format-valid"||!assurance(&value,"schema-policy")||rows.len()!=fields(round).ok_or(())?.len(){return Err(());}
        for(row,(id,_,text))in rows.iter().zip(fields(round).ok_or(())?){if row["id"]!=*id||row["valid"]!=true||row["issues"]!=json!([])||row["characterCount"]!=text.len()||!row["limit"].as_u64().is_some_and(|n|n>=text.len() as u64&&n<=32768){return Err(());}}
        self.validations.push(value);Ok(())
    }
    pub(super) fn report(&self,fixture:&Fixture)->Option<Value>{if self.open_pending.is_some()||self.passive_pending.is_some()||self.validation_pending.is_some()||self.proposal_pending
        ||!self.capability||!self.config_blocked||self.sessions.len()!=self.case.sessions()||!self.sessions.iter().all(Session::complete)
        ||self.observations.len()!=match self.case{Case::Metadata=>4,Case::Version=>2,Case::Workflow=>0}
        ||self.case==Case::Metadata&&(!self.selection_visible||self.validations.len()!=2)||fixture.completed!=self.case.sessions(){return None;}
        Some(json!({"case":self.case.name(),"domain":self.case.domain(),"sameOriginalSessions":self.sessions.len(),"originalFinalities":true,
            "visibleReviewAndResult":true,"passiveReadbacks":self.observations.len()/2,"fixture":fixture.report(),
            "sessions":self.sessions.iter().map(|s|json!({"apply":s.apply_requested,"close":s.close_requested,"outcome":s.projection["coreOutcome"],
                "writerFrames":if s.apply_requested{3}else{2},"stdoutFrames":3,"originalsJoined":s.finality.as_ref().is_some_and(|f|f.matches(&s.projection)),"fileReadback":s.readback})).collect::<Vec<_>>(),
            "controlIntegrationOnly":true,"physicalDropdownGestureQualified":false,"imagesDoctorVaultRestartQualified":false}))
    }
}
// Every entry below is called by the existing shell immediately around the real
// command. These are borrowed comparison hooks, not another invoker/owner.
impl Observation {
    pub(crate) fn local_case(&self)->bool{matches!(self.case,super::Case::LocalEdits(_))}
    fn local(&self,f:impl FnOnce(&mut Record,Option<Step>,&str)->Result<(),()>){
        if !self.local_case(){return;}if !self.timely(){return;}
        let Some(mut r)=self.record()else{return;};let step=if let super::Step::LocalEdits(s)=r.step{Some(s)}else{None};
        let project=r.project.as_ref().map(|p|p.id.clone()).unwrap_or_default();
        let result=r.local_edits.as_mut().ok_or(()).and_then(|record|f(record,step,&project));
        if result.is_err(){self.fail_with("local-edits-original-contract");}else{self.timely();}
    }
    fn local_status_value(&self,case:Case,value:Result<Value,()>,returned:Option<&str>,edits:&EditOwner){
        if self.case!=super::Case::LocalEdits(case){return;}
        let Ok(value)=value else{self.fail_with("local-edits-original-contract");return;};
        let p=if value["active"].is_null(){&value["lastTerminal"]}else{&value["active"]};
        let facts=p["sessionId"].as_str().filter(|_|p["phase"]=="final").and_then(|id|match case{
            Case::Workflow=>edits.installed_workflow_observation_final(id).map(Finality::Workflow),
            Case::Metadata=>edits.installed_metadata_observation_final(id).map(Finality::Metadata),
            Case::Version=>edits.installed_version_observation_final(id).map(Finality::Version)});
        self.local(|r,_,_|r.status(value,returned,facts));
    }
    pub(crate) fn local_poll(&self,edits:&EditOwner){
        match self.case {super::Case::LocalEdits(Case::Workflow)=>self.local_status_value(Case::Workflow,edits.workflow_status().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),None,edits),
            super::Case::LocalEdits(Case::Metadata)=>self.local_status_value(Case::Metadata,edits.metadata_text_status().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),None,edits),
            super::Case::LocalEdits(Case::Version)=>self.local_status_value(Case::Version,edits.release_version_status().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),None,edits),_=>{}}
    }
    pub(crate) fn local_config_status(&self,status:&ConfigEditStatus){
        if !self.local_case(){return;}
        if let Some(mut parent)=self.record(){
            if status.capability.available&&status.capability.reason==edit::EditAvailability::Available {parent.capability=true;}
        }
        self.local(|r,_,_|{
        if status.schema_version!=1||!edit::token(&status.window_generation)||r.generation.as_ref().is_some_and(|g|g!=&status.window_generation)
            ||status.active.is_some()||status.last_terminal.is_some(){return Err(());}
        r.generation=Some(status.window_generation.clone());
        if status.capability.reason==edit::EditAvailability::OtherEditActive&&!status.capability.available{r.config_blocked=true;if let Some(s)=r.sessions.last_mut(){if s.finality.is_none(){s.config_blocked=true;}}}
        else if !(status.capability.available&&status.capability.reason==edit::EditAvailability::Available)
            &&!(status.capability.reason==edit::EditAvailability::Shutdown&&r.sessions.len()==r.case.sessions()&&r.sessions.iter().all(Session::complete)){return Err(());}Ok(())});}
    fn local_open(&self,case:Case,project:&str,platform_arg:Option<&str>,locale:Option<&str>){self.local(|r,step,selected|{
        let index=match step{Some(Step::Open(i)|Step::Opened(i))if case==Case::Version||case==Case::Workflow=>usize::from(i),
            Some(Step::Prepare(i)|Step::OpenText(i))if case==Case::Metadata=>usize::from(i),_=>return Err(())};
        if r.case!=case||project!=selected||selected.is_empty()||case==Case::Metadata&&(platform_arg!=platform(index)||locale!=Some("en-US")){return Err(());}r.open_request(index,project)
    });}
    pub(crate) fn workflow_open_request(&self,project:&str){self.local_open(Case::Workflow,project,None,None);}
    pub(crate) fn metadata_open_request(&self,args:&crate::metadata_text_commands::Open){self.local_open(Case::Metadata,&args.project_id,Some(match args.platform{metadata::Platform::Android=>"android",metadata::Platform::Ios=>"ios"}),Some(&args.locale));}
    pub(crate) fn version_open_request(&self,args:&crate::release_version_edit_commands::Open){self.local_open(Case::Version,&args.project_id,None,None);}
    pub(crate) fn workflow_prepare_request(&self,args:&workflow::PrepareWorkflowEdit){
        let body=json!({"sessionId":args.session_id,"revision":args.revision,"draft":args.draft,"toolingRepository":args.tooling_repository,"toolingSha":args.tooling_sha,"draftRevision":args.draft_revision,"baselineGeneration":args.baseline_generation});
        self.local(|r,step,_|{if r.case!=Case::Workflow||!matches!(step,Some(Step::Open(_)|Step::Opened(_)|Step::OpenText(_))){return Err(());}r.prepare_request(body,&self.base)});
    }
    pub(crate) fn metadata_prepare_request(&self,args:&metadata::PrepareMetadataTextEdit){
        let body=json!({"sessionId":args.session_id,"revision":args.revision,"expectedBaseline":args.expected_baseline,"fields":args.fields,"draftRevision":args.draft_revision,"baselineGeneration":args.baseline_generation});
        self.local(|r,step,_|{if r.case!=Case::Metadata||!matches!(step,Some(Step::Prepare(_)|Step::OpenText(_))){return Err(());}r.prepare_request(body,&self.base)});
    }
    pub(crate) fn version_prepare_request(&self,args:&version::PrepareReleaseVersionEdit){
        let body=json!({"sessionId":args.session_id,"revision":args.revision,"expectedBaseline":args.expected_baseline,"intent":args.intent,"values":args.values,"draftRevision":args.draft_revision,"baselineGeneration":args.baseline_generation});
        self.local(|r,step,_|{if r.case!=Case::Version||!matches!(step,Some(Step::Prepare(0)|Step::Review(0))){return Err(());}r.prepare_request(body,&self.base)});
    }
    fn local_apply(&self,case:Case,id:&str,token:&str){self.local(|r,step,_|{
        if r.case!=case||!matches!(step,Some(Step::Apply(_)|Step::Result(_))){return Err(());}r.apply_request(id,token)});}
    pub(crate) fn workflow_apply_request(&self,id:&str,token:&str){self.local_apply(Case::Workflow,id,token);}
    pub(crate) fn metadata_apply_request(&self,id:&str,token:&str){self.local_apply(Case::Metadata,id,token);}
    pub(crate) fn version_apply_request(&self,id:&str,token:&str){self.local_apply(Case::Version,id,token);}
    pub(crate) fn workflow_close_request(&self){self.local(|r,step,_|{if !matches!(step,Some(Step::CloseReview|Step::Closed)){return Err(());}r.close_request()});}
    pub(crate) fn metadata_close_request(&self,_id:&str){if self.local_case(){self.fail_with("local-edits-original-contract");}}
    pub(crate) fn version_close_request(&self,_id:&str){if self.local_case(){self.fail_with("local-edits-original-contract");}}
    pub(crate) fn local_release_version_request(&self,body:&Value){self.local(|r,step,project|{if r.case!=Case::Version{return Err(());}r.passive_request(step.ok_or(())?,body,project)});}
    pub(crate) fn local_release_version(&self,result:&Result<crate::release_version_protocol::Observation,BridgeError>){self.local(|r,_,_|r.passive_result(serde_json::to_value(result.as_ref().map_err(|_|())?).map_err(|_|())?));}
    pub(crate) fn metadata_request(&self,body:&Value){self.local(|r,step,project|{if r.case!=Case::Metadata{return Err(());}r.passive_request(step.ok_or(())?,body,project)});}
    pub(crate) fn metadata_observation(&self,result:&Result<metadata::Observation,BridgeError>){self.local(|r,_,_|r.passive_result(serde_json::to_value(result.as_ref().map_err(|_|())?).map_err(|_|())?));}
    pub(crate) fn metadata_validation_request(&self,body:&Value){self.local(|r,step,_|{
        let Some(Step::Validate(i)|Step::Validated(i))=step else{return Err(());};let i=usize::from(i);
        if r.case!=Case::Metadata||r.validation_pending.is_some()||r.validations.len()!=i||body!=&json!({"platform":platform(i).ok_or(())?,"fields":text_values(i).ok_or(())?}){return Err(());}r.validation_pending=Some(i);Ok(())});}
    pub(crate) fn metadata_validation(&self,result:&Result<metadata::ValidationResult,BridgeError>){self.local(|r,_,_|r.validation_result(serde_json::to_value(result.as_ref().map_err(|_|())?).map_err(|_|())?));}
    pub(crate) fn local_github_request(&self,body:&Value){self.local(|r,step,_|{
        if r.case!=Case::Workflow||!matches!(step,Some(Step::Propose|Step::Proposal))||r.proposal_pending||r.proposal.is_some()
            ||body!=&json!({"draft":self.base,"toolingRepository":REPOSITORY,"toolingSha":PIN,"suppliedSnapshot":null}){return Err(());}r.proposal_pending=true;Ok(())});}
    pub(crate) fn local_github_proposal(&self,result:&Result<Value,BridgeError>){self.local(|r,_,_|{
        let value=result.as_ref().map_err(|_|())?;let workflows=value["workflows"].as_array().ok_or(())?;
        if !r.proposal_pending||r.proposal.is_some()||value["schemaVersion"]!=1||value["state"]!="proposed"||!format_valid(&value["validation"])
            ||value["facts"]!=json!({"githubContacted":false,"repositoryObserved":false,"toolingRefResolved":false,
                "templateCompatibility":"unknown","comparisonBasis":"caller-supplied-digest-summary","snapshotProvided":false,"applyAvailable":false})
            ||value["templateSet"]!=json!({"coreVersion":crate::runtime::CORE_VERSION,"resourceVersion":1,"resourceSha256":RESOURCE})
            ||value["tooling"]!=json!({"repository":REPOSITORY,"sha":PIN,"schemaReference":format!("https://raw.githubusercontent.com/{REPOSITORY}/{PIN}/schemas/project.schema.json"),"state":"format-only"})
            ||value["settings"]["configPath"]!="release/mobile-release.json"||value["settings"]["sourcePolicy"]!=json!({
                "candidateBranch":self.base["source"]["candidateBranch"],"productionBranch":self.base["source"]["productionBranch"],"basis":"configured-policy"})
            ||!assurance(value,"schema-policy")||workflows.len()!=4{return Err(());}
        for(row,(id,path,size))in workflows.iter().zip(WORKFLOWS){let text=row["content"].as_str().ok_or(())?;
            if row.as_object().is_none_or(|m|m.len()!=7)||row["id"]!=id||row["path"]!=path||row["byteLength"]!=size||row["comparison"]!="not-supplied"
                ||text.len()!=size||text.encode_utf16().count()>4096||!text.ends_with('\n')||text.matches(PIN).count()!=2||row["sha256"]!=digest(text.as_bytes()){return Err(());}}
        r.proposal_pending=false;r.proposal=Some(Value::Array(workflows.clone()));Ok(())});}
}
macro_rules! status_hooks {($case:ident,$ty:ty,$open:ident,$prepare:ident,$apply:ident,$close:ident,$status:ident)=>{
    impl Observation {
        pub(crate) fn $open(&self,result:&Result<$ty,BridgeError>,edits:&EditOwner){self.local_status_value(Case::$case,result.as_ref().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),Some("open"),edits);}
        pub(crate) fn $prepare(&self,result:&Result<$ty,BridgeError>,edits:&EditOwner){self.local_status_value(Case::$case,result.as_ref().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),Some("prepare"),edits);}
        pub(crate) fn $apply(&self,result:&Result<$ty,BridgeError>,edits:&EditOwner){self.local_status_value(Case::$case,result.as_ref().map_err(|_|()).and_then(|s|serde_json::to_value(s).map_err(|_|())),Some("apply"),edits);}
        pub(crate) fn $close(&self,_result:&Result<$ty,BridgeError>,_edits:&EditOwner){if self.local_case(){self.fail_with("local-edits-original-contract");}}
        pub(crate) fn $status(&self,status:&$ty,edits:&EditOwner){self.local_status_value(Case::$case,serde_json::to_value(status).map_err(|_|()),None,edits);}
    }
}}
status_hooks!(Workflow,workflow::WorkflowEditStatus,workflow_open_result,workflow_prepare_result,workflow_apply_result,local_unused_workflow_close_result,workflow_status);
status_hooks!(Metadata,metadata::MetadataTextEditStatus,metadata_open_result,metadata_prepare_result,metadata_apply_result,metadata_close_result,metadata_edit_status);
status_hooks!(Version,version::ReleaseVersionEditStatus,version_open_result,version_prepare_result,version_apply_result,version_close_result,version_edit_status);

// SOURCE-derived existing version control/readback script, only original edit route 1.
#[derive(Clone,Copy)]
enum VersionStep {
    InitialLoad, InitialRead, Open(u8), ReadOpen(u8), Name(u8), Build(u8), ReadInputs(u8), Review(u8), ReadReview(u8),
    Confirm(u8), ReadConfirmation(u8), Check(u8), ReadChecked(u8), Type(u8), ReadTyped(u8),
    Apply(u8), ReadSaved(u8), Readback(u8), ReadReadback(u8),
}
impl VersionStep {
    fn index(self) -> usize { usize::from(match self {
        Self::InitialLoad | Self::InitialRead => 1,
        Self::Open(i) | Self::ReadOpen(i) | Self::Name(i) | Self::Build(i) | Self::ReadInputs(i)
        | Self::Review(i) | Self::ReadReview(i) | Self::Confirm(i) | Self::ReadConfirmation(i)
        | Self::Check(i) | Self::ReadChecked(i) | Self::Type(i) | Self::ReadTyped(i)
        | Self::Apply(i) | Self::ReadSaved(i) | Self::Readback(i) | Self::ReadReadback(i) => i,
    }) }
}
fn version_script(step: VersionStep) -> Option<String> {
    let index = step.index(); if index != 1 { return None; }
    let body = match step {
        VersionStep::InitialLoad => r#"const p=passive();if(p.button.disabled||p.live.getAttribute('aria-busy')==='true')return {state:'wait'};if(document.querySelector('dialog'))throw 0;show(p.button);p.button.click();return {state:'ready'};"#,
        VersionStep::InitialRead => r#"const p=passive();if(p.button.disabled||p.live.getAttribute('aria-busy')==='true'||!p.live.querySelector('strong.summary-value'))return {state:'wait'};return {state:'ready',readback:readback(p)};"#,
        VersionStep::Open(_) => r#"const e=editor(),b=openButton(e);if (b.disabled) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(b);b.click();return {state:'ready'};"#,
        VersionStep::ReadOpen(_) => r#"const e=editor();if (!e.querySelector('.version-selection')) return {state:'wait'};
            const m=controls();if (!m.open.disabled || phase>0 && m.review.disabled) return {state:'wait'};
            return {state:'ready',display:display(m)};"#,
        VersionStep::Name(_) if index < 2 => r#"return insert(0,phase===0?'1.2.3':'2.3.4',phase===0?['','']:['1.2.3','7']);"#,
        VersionStep::Build(_) if index < 2 => r#"return insert(1,phase===0?'7':'8',phase===0?['1.2.3','']:['2.3.4','7']);"#,
        VersionStep::Name(_) | VersionStep::Build(_) => return None,
        VersionStep::ReadInputs(_) => r#"const m=controls();return {state:'ready',display:display(m)};"#,
        VersionStep::Review(_) => r#"const m=controls();if (m.review.disabled) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(m.review);m.review.click();return {state:'ready'};"#,
        VersionStep::ReadReview(_) => r#"const m=controls();if (!m.editor.querySelector('.version-review')) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;return {state:'ready',display:display(m),review:review(m)};"#,
        VersionStep::Confirm(_) => r#"const m=controls(),buttons=[...m.editor.querySelectorAll(':scope > button.button.primary')];
            const label=['Create version file…','Save version values…','Confirm unchanged values…'][phase];
            if (buttons.length!==1 || text(buttons[0])!==label || buttons[0].disabled || document.querySelector('dialog')) throw 0;
            show(buttons[0]);buttons[0].click();return {state:'ready'};"#,
        VersionStep::ReadConfirmation(_) | VersionStep::ReadChecked(_) | VersionStep::ReadTyped(_) => r#"if (!document.querySelector('.version-editor > dialog[open].confirm-dialog')) return {state:'wait'};
            return {state:'ready',confirmation:confirmationDisplay()};"#,
        VersionStep::Check(_) => r#"const c=confirmation();if (c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.check);c.check.click();return {state:'ready'};"#,
        VersionStep::Type(_) => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.input);c.input.focus();c.input.select();if (document.activeElement!==c.input || c.input.selectionStart!==0 || c.input.selectionEnd!==0
                || !document.execCommand('insertText',false,'SAVE')) throw 0;return {state:'ready'};"#,
        VersionStep::Apply(_) => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='SAVE' || c.apply.disabled) throw 0;
            show(c.apply);c.apply.click();return {state:'ready'};"#,
        VersionStep::ReadSaved(_) => r#"const m=controls();if (document.querySelector('dialog') || m.open.disabled || m.review.disabled) return {state:'wait'};
            return {state:'ready',display:display(m),outcome:outcome(m)};"#,
        VersionStep::Readback(_) => r#"const p=passive();if (p.button.disabled || p.live.getAttribute('aria-busy')==='true') return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(p.button);p.button.click();return {state:'ready'};"#,
        VersionStep::ReadReadback(_) => r#"const m=controls(),p=passive();if (p.button.disabled || p.live.getAttribute('aria-busy')==='true') return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;return {state:'ready',display:display(m),outcome:outcome(m),readback:readback(p)};"#,
    };
    // The actual original handler/status hooks separately attest every native
    // boundary. This script only operates and reads existing visible controls.
    let phase = format!("const phase={index};");
    Some([r#"(() => { try {
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger')) throw 0;
        const text=e=>{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0;return e.textContent;};
        const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';};
        const show=e=>{if (!e) throw 0;e.scrollIntoView({block:'center'});if (!visible(e)) throw 0;};
        const selected=()=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')==='Dashboard');
        const editor=()=>{
            const editors=document.querySelectorAll('section[aria-label="Edit or create saved version values"]');
            if (!selected() || editors.length!==1) throw 0;const e=editors[0];
            if (e.querySelector('.notice-danger, .review-caution, [role="alert"]')) throw 0;return e;
        };
        const openButton=e=>{
            const groups=e.querySelectorAll(':scope > .button-row');if (groups.length<1 || groups.length>2) throw 0;
            const buttons=groups[0].querySelectorAll(':scope > button');
            if (buttons.length!==3 || text(buttons[0])!=='Open saved version editor'
                || text(buttons[1])!=='Project Settings / ignore prerequisite' || text(buttons[2])!=='Check writer availability') throw 0;
            return buttons[0];
        };
        const controls=()=>{
            const e=editor(),groups=e.querySelectorAll(':scope > .button-row');
            const fields=[...e.querySelectorAll(':scope > .version-values > div')];
            if (groups.length!==2 || fields.length!==2) throw 0;
            const inputs=fields.map((field,index)=>{
                const input=field.querySelector(':scope > input'),label=field.querySelector(':scope > label');
                if (!input || !label || !input.id || label.getAttribute('for')!==input.id || input.disabled || input.readOnly
                    || input.type!=='text' || input.maxLength!==(index===0?64:10)
                    || !text(label).startsWith(index===0?'Marketing version':'Build number') || input.value.length>(index===0?64:10)) throw 0;
                return input;
            });
            const buttons=groups[1].querySelectorAll(':scope > button');
            if (buttons.length!==3 || !['Validate and review creation','Validate and review values'].includes(text(buttons[0]))
                || text(buttons[1])!=='Discard value changes' || text(buttons[2])!=='Reload saved values') throw 0;
            return {editor:e,open:openButton(e),review:buttons[0],inputs};
        };
        const display=m=>{
            const e=m.editor,selection=e.querySelectorAll(':scope > .version-selection');
            if (selection.length!==1) throw 0;const paragraphs=selection[0].querySelectorAll(':scope > p');
            const digests=selection[0].querySelectorAll(':scope > code.version-digest');
            if (paragraphs.length!==3 || digests.length<1 || digests.length>2) throw 0;
            [...paragraphs,...digests,...m.inputs].forEach(show);
            return {title:text(e.querySelector(':scope > .section-heading h2')),project:text(e.querySelector(':scope > p')),
                badge:text(e.querySelector(':scope > .section-heading .badge')),selection:[...paragraphs].map(text),digests:[...digests].map(text),
                values:{name:m.inputs[0].value,build:m.inputs[1].value},openAvailable:!m.open.disabled,
                reviewLabel:text(m.review),reviewAvailable:!m.review.disabled};
        };
        const insert=(index,replacement,before)=>{
            const m=controls();if (document.querySelector('dialog') || m.inputs.some((input,i)=>input.value!==before[i])) throw 0;
            const input=m.inputs[index];show(input);input.focus();input.select();
            if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==before[index].length
                || !document.execCommand('insertText',false,replacement)) throw 0;return {state:'ready'};
        };
        const raw=(element,before)=>{
            if (text(element.querySelector(':scope > h4'))!==(before?'Complete original text':'Complete reviewed text')) throw 0;
            const pres=element.querySelectorAll(':scope > pre');show(element);
            if (before && pres.length===0) {
                if (text(element.querySelector(':scope > p'))!=='Observed absent. Empty or malformed files are not treated as absence.') throw 0;
                return {state:'absent'};
            }
            if (pres.length!==1 || pres[0].getAttribute('aria-label')!=='Complete '+(before?'original':'reviewed')+' version source') throw 0;
            show(pres[0]);const content=text(pres[0].querySelector(':scope > code'));
            const size=/^([0-9]+) UTF-8 bytes · lf · Final line ending present$/.exec(text(element.querySelector(':scope > p')));
            const digest=/^SHA256 ([0-9a-f]{64})$/.exec(text(element.querySelector(':scope > code.version-digest')));
            if (!size || !digest) throw 0;const bytes=Number(size[1]);
            if (!Number.isSafeInteger(bytes) || String(bytes)!==size[1] || bytes>4096) throw 0;
            const value={text:content,bytes,sha256:digest[1]};return before?{state:'present',...value}:value;
        };
        const review=m=>{
            const views=m.editor.querySelectorAll(':scope > .version-review');if (views.length!==1) throw 0;const view=views[0];
            const facts=view.querySelectorAll(':scope > p'),sides=view.querySelectorAll('.version-raw-grid > .version-raw');
            if (facts.length!==6 || sides.length!==2) throw 0;[...facts].forEach(show);
            return {title:text(view.querySelector(':scope > h3')),facts:[...facts].map(text),before:raw(sides[0],true),after:raw(sides[1],false)};
        };
        const confirmation=()=>{
            const e=editor(),dialogs=document.querySelectorAll('dialog');
            if (dialogs.length!==1 || dialogs[0].parentElement!==e || !dialogs[0].classList.contains('confirm-dialog')
                || !dialogs[0].open || dialogs[0].querySelector('[role="alert"]')) throw 0;
            const dialog=dialogs[0],checks=dialog.querySelectorAll('.save-confirm-check input[type="checkbox"]');
            const inputs=dialog.querySelectorAll('.dialog-content > input'),buttons=dialog.querySelectorAll('.button-row > button');
            if (checks.length!==1 || inputs.length!==1 || buttons.length!==2 || checks[0].disabled || inputs[0].disabled || inputs[0].readOnly
                || inputs[0].type!=='text' || inputs[0].value.length>4 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing'
                || text(buttons[1])!==['Create version file','Save version values','Confirm unchanged values'][phase]
                || text(dialog.querySelector('.save-confirm-check'))!=='I reviewed the full original/after text, exact destination, byte comparisons, mode and directory/line-ending facts.') throw 0;
            return {dialog,check:checks[0],input:inputs[0],apply:buttons[1]};
        };
        const confirmationDisplay=()=>{
            const c=confirmation(),paragraphs=c.dialog.querySelectorAll('.dialog-content > p');
            if (paragraphs.length!==2) throw 0;[c.check,c.input,c.apply,...paragraphs].forEach(show);
            return {title:text(c.dialog.querySelector('h2')),selection:text(paragraphs[0]),scope:text(paragraphs[1]),
                checked:c.check.checked,typed:c.input.value,applyAvailable:!c.apply.disabled};
        };
        const outcome=m=>{
            const panels=m.editor.querySelectorAll(':scope > .version-status'),notices=panels.length===1?panels[0].querySelectorAll(':scope > .notice-info'): [];
            if (panels.length!==1 || notices.length!==1 || notices[0].getAttribute('role')!=='status') throw 0;
            const content=notices[0].querySelector(':scope > div'),paragraphs=content?.querySelectorAll(':scope > p');
            if (!content || paragraphs.length!==3
                || text(paragraphs[2])!=='This receipt is for the submitted revision only, not later edits. Read saved version again explicitly before using its new values for build consent.') throw 0;
            show(content);return {title:text(content.querySelector(':scope > strong')),submitted:text(paragraphs[0]),facts:text(paragraphs[1])};
        };
        const passive=()=>{
            const cards=document.querySelectorAll('section[aria-label="Saved version and build"]');
            if (!selected() || cards.length!==1) throw 0;const card=cards[0],live=card.querySelector('div[aria-live="polite"]'),buttons=card.querySelectorAll(':scope > button');
            if (!live || buttons.length!==1 || text(buttons[0])!=='Read saved version') throw 0;return {card,live,button:buttons[0]};
        };
        const readback=p=>{
            const name=p.live.querySelector('strong.summary-value'),paragraphs=[...p.live.querySelectorAll(':scope > p')];
            const badges=p.live.querySelectorAll(':scope > .badge'),scope=p.card.querySelectorAll(':scope > p');
            if (p.live.getAttribute('aria-busy')!=='false' || p.live.children.length!==4 || paragraphs.length!==2 || badges.length!==1 || scope.length!==1) throw 0;
            const sources=paragraphs[1].querySelectorAll(':scope > code');if (sources.length!==1) throw 0;
            [p.card,name,...paragraphs,badges[0],scope[0],p.button].forEach(show);
            return {name:text(name),build:text(paragraphs[0]),badge:text(badges[0]),source:text(sources[0]),sourceText:text(paragraphs[1]),
                scope:text(scope[0]),config:text(p.card.querySelector('.summary-foot code')),readAvailable:!p.button.disabled};
        };
    "#,&phase,body,r#" } catch { return {state:'error'}; } })()"#].concat())
}



fn metadata_script(step:Step)->Option<String>{
    let round=match step{Step::Context(i)|Step::Load(i)|Step::Loaded(i)|Step::Fill(i,_)|Step::Inputs(i)|Step::Validate(i)|Step::Validated(i)
        |Step::Prepare(i)|Step::OpenText(i)|Step::Review(i)|Step::Confirm(i)|Step::Confirmation(i)|Step::Check(i)|Step::Checked(i)
        |Step::Type(i)|Step::Typed(i)|Step::Apply(i)|Step::Result(i)|Step::Refresh(i)|Step::Readback(i)=>usize::from(i),Step::Navigate=>0,_=>return None};
    if round>1{return None;}
    let body=match step {
        Step::Navigate=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Metadata"]');if(!b||b.disabled||document.querySelector('dialog'))throw 0;show(b);b.click();return {state:'ready'};"#.to_owned(),
        // A bounded standard HTML select interaction, not native dropdown/key accessibility qualification.
        Step::Context(1)=>r#"if(!selected('Metadata'))return {state:'wait'};const selects=document.querySelectorAll('.metadata-context-row select');
            if(selects.length!==1||selects[0].disabled||document.querySelector('dialog'))throw 0;const s=selects[0],options=[...s.options];
            if(options.length!==3||options[0].value!==''||!options[0].disabled||text(options[0])!=='No enabled configured locale'||options[0].parentElement!==s)throw 0;
            if(options.slice(1).some((o,i)=>text(o)!==['android / en-US','ios / en-US'][i]||!o.value||o.disabled||o.parentElement?.getAttribute('label')!=='Current saved configuration')
                ||options[1].value===options[2].value||s.selectedIndex!==1||s.value!==options[1].value)throw 0;
            show(s);s.selectedIndex=2;s.dispatchEvent(new Event('change',{bubbles:true}));return {state:'ready'};"#.to_owned(),
        Step::Load(_)=>r#"if(!selected('Metadata')||!document.querySelector('.metadata-text-editor'))return {state:'wait'};const m=controls();if(m.load.disabled)return {state:'wait'};
            if(text(m.load)!=='Load public text'||!m.validate.disabled||!m.review.disabled||m.editor.querySelector('.metadata-text-fields'))throw 0;show(m.load);m.load.click();return {state:'ready'};"#.to_owned(),
        Step::Loaded(_)=>r#"const m=controls();if(m.load.disabled||text(m.load)!=='Refresh text'||!m.editor.querySelector('.metadata-text-fields'))return {state:'wait'};return {state:'ready',display:display(m)};"#.to_owned(),
        Step::Fill(_,i)=>{
            let fields=fields(round)?;let i=usize::from(i);let(_,before,after)=fields.get(i)?;if *before==Some(*after){return None;}
            let initial=fields.iter().enumerate().map(|(j,(_,old,new))|if j<i{*new}else{old.unwrap_or("")}).collect::<Vec<_>>();
            format!("return insert({i},{},{});",serde_json::to_string(after).ok()?,serde_json::to_string(&initial).ok()?)
        },
        Step::Inputs(_)=>r#"const m=controls();return {state:'ready',display:display(m)};"#.to_owned(),
        Step::Validate(_)=>r#"const m=controls();if(m.validate.disabled||!m.review.disabled||m.editor.querySelector('.metadata-validation-status'))throw 0;show(m.validate);m.validate.click();return {state:'ready'};"#.to_owned(),
        Step::Validated(_)=>r#"const m=controls();if(m.validate.disabled||m.review.disabled||!m.editor.querySelector('.metadata-validation-status'))return {state:'wait'};return {state:'ready',display:display(m)};"#.to_owned(),
        Step::Prepare(_)=>r#"const m=controls();if(m.review.disabled)return {state:'wait'};if(document.querySelector('dialog'))throw 0;show(m.review);m.review.click();return {state:'ready'};"#.to_owned(),
        Step::OpenText(_)=>r#"if(!document.querySelector('.metadata-native-review'))return {state:'wait'};const p=panel();if(text(p.querySelector('.section-heading h2'))!=='Review text changes')return {state:'wait'};
            const details=p.querySelectorAll('.metadata-file-review');if(details.length!==ids.length||document.querySelector('dialog'))throw 0;
            for(const d of details){const summary=d.querySelector(':scope > summary');show(summary);if(!d.open)summary.click();}return {state:'ready'};"#.to_owned(),
        Step::Review(_)=>r#"const m=controls(),p=panel();if(text(p.querySelector('.section-heading h2'))!=='Review text changes')return {state:'wait'};if(document.querySelector('dialog'))throw 0;return {state:'ready',review:review(),draft:rows(m).map(r=>({id:r.id,text:r.input.value}))};"#.to_owned(),
        Step::Confirm(_)=>r#"const p=panel(),buttons=[...p.querySelectorAll(':scope > .button-row button.primary')];if(buttons.length!==1||buttons[0].disabled||text(buttons[0])!=='Save text…'||document.querySelector('dialog'))throw 0;show(buttons[0]);buttons[0].click();return {state:'ready'};"#.to_owned(),
        Step::Confirmation(_)|Step::Checked(_)|Step::Typed(_)=>r#"if(!document.querySelector('dialog[open].metadata-confirm-dialog'))return {state:'wait'};return {state:'ready',confirmation:confirmationDisplay()};"#.to_owned(),
        Step::Check(_)=>r#"const c=confirmation();if(c.check.checked||c.input.value!==''||!c.apply.disabled)throw 0;show(c.check);c.check.click();return {state:'ready'};"#.to_owned(),
        Step::Type(_)=>r#"const c=confirmation();if(!c.check.checked||c.input.value!==''||!c.apply.disabled)throw 0;show(c.input);c.input.focus();c.input.select();if(document.activeElement!==c.input||c.input.selectionStart!==0||c.input.selectionEnd!==0||!document.execCommand('insertText',false,'SAVE'))throw 0;return {state:'ready'};"#.to_owned(),
        Step::Apply(_)=>r#"const c=confirmation();if(!c.check.checked||c.input.value!=='SAVE'||c.apply.disabled)throw 0;show(c.apply);c.apply.click();return {state:'ready'};"#.to_owned(),
        Step::Result(_)|Step::Readback(_)=>r#"const m=controls(),p=panel();if(document.querySelector('dialog')||text(p.querySelector('.section-heading h2'))!=='Text saved'||m.load.disabled)return {state:'wait'};return {state:'ready',display:display(m),outcome:outcome()};"#.to_owned(),
        Step::Refresh(_)=>r#"const m=controls();if(m.load.disabled||text(m.load)!=='Refresh text'||document.querySelector('dialog'))throw 0;show(m.load);m.load.click();return {state:'ready'};"#.to_owned(),
        _=>return None,
    };
    Some([r#"(() => { try {
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .metadata-save-panel .notice-danger')) throw 0;
        const text=e=>{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0;return e.textContent;};
        const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';};
        const show=e=>{if (!e) throw 0;e.scrollIntoView({block:'center'});if (!visible(e)) throw 0;};
        const selected=label=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')===label);
        const localRound=__ROUND__;const platform=localRound===0?'android':'ios';const ids=localRound===0?['title.txt','short_description.txt','full_description.txt']:['description.txt','keywords.txt','privacy_url.txt','support_url.txt','release_notes.txt'];
        const controls=()=>{
            const editors=document.querySelectorAll('.metadata-text-editor');if (!selected('Metadata') || editors.length!==1) throw 0;
            const editor=editors[0];if (editor.querySelector('.notice-danger, .notice-warning, .review-caution, .issues, .metadata-latest-observation')) throw 0;
            const contexts=editor.querySelectorAll('.metadata-context-row select'),loads=editor.querySelectorAll('.metadata-context-row > button.button.secondary');
            const validations=editor.querySelectorAll('.metadata-text-actions > button.button.secondary'),reviews=editor.querySelectorAll('.metadata-text-actions > button.button.primary');
            if (contexts.length!==1 || loads.length!==1 || validations.length!==1 || reviews.length!==1) throw 0;
            const context=contexts[0];if (context.disabled || !context.value || context.selectedOptions.length!==1
                || text(context.selectedOptions[0])!==platform+' / en-US' || context.selectedOptions[0].parentElement?.getAttribute('label')!=='Current saved configuration'
                || text(reviews[0])!=='Review changes') throw 0;
            return {editor,context,load:loads[0],validate:validations[0],review:reviews[0]};
        };
        const rows=m=>{
            const elements=[...m.editor.querySelectorAll('.metadata-text-fields > .metadata-text-field')];if (elements.length!==ids.length) throw 0;
            return elements.map((row,index)=>{const codes=row.querySelectorAll(':scope > code'),inputs=row.querySelectorAll(':scope > textarea');
                if (codes.length!==1 || inputs.length!==1) throw 0;const input=inputs[0],id=ids[index],path=text(codes[0]);
                if (path!=='release/store/'+platform+'/en-US/'+id || input.disabled || input.readOnly || input.value.length>32768
                    || !input.id || row.querySelector('.inline-heading label')?.getAttribute('for')!==input.id) throw 0;
                return {row,input,id,path};});
        };
        const display=m=>{
            if (text(m.validate)!=='Validate text') throw 0;
            const statuses=m.editor.querySelectorAll('.metadata-validation-status');if (statuses.length>1) throw 0;
            const fields=rows(m).map(item=>{show(item.row);show(item.input);const badges=[...item.row.querySelectorAll('.inline-heading .badge')];if (badges.length!==2) throw 0;
                return {id:item.id,path:item.path,text:item.input.value,badges:badges.map(text),invalid:item.input.getAttribute('aria-invalid')};});
            return {context:text(m.context.selectedOptions[0]),badge:text(m.editor.querySelector('.section-heading .badge')),fields,
                loadLabel:text(m.load),loadAvailable:!m.load.disabled,validateAvailable:!m.validate.disabled,reviewAvailable:!m.review.disabled,
                validation:statuses.length?text(statuses[0].querySelector('.badge')):null};
        };
        const insert=(index,replacement,before)=>{
            const m=controls(),items=rows(m);if (m.load.disabled || m.validate.disabled || !m.review.disabled || text(m.load)!=='Refresh text'
                || m.editor.querySelector('.metadata-validation-status') || items.some((item,offset)=>item.input.value!==before[offset])) throw 0;
            const input=items[index].input;show(input);input.focus();input.select();
            if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==before[index].length
                || !document.execCommand('insertText',false,replacement)) throw 0;return {state:'ready'};
        };
        const panel=()=>{const panels=document.querySelectorAll('.metadata-save-panel');if (!selected('Metadata') || panels.length!==1) throw 0;return panels[0];};
        const raw=(element,path,before)=>{
            if (text(element.querySelector('h4'))!==(before?'Original bytes':'Reviewed replacement bytes')) throw 0;
            const pres=element.querySelectorAll('pre');show(element);
            if (before && pres.length===0) {if (text(element.querySelector('p'))!=='Observed absent. No original text was fabricated.') throw 0;return {state:'absent'};}
            if (pres.length!==1 || pres[0].getAttribute('aria-label')!==`Complete ${before?'original':'reviewed'} public text for ${path}`) throw 0;
            show(pres[0]);const content=text(pres[0].querySelector('code'));
            const numbers=/^(.+) UTF-8 bytes · No line endings · No final line ending$/.exec(text(element.querySelector('p')));
            const digest=/^SHA256 ([0-9a-f]{64})$/.exec(text(element.querySelector('.metadata-digest')));
            if (!numbers || !digest) throw 0;const byteLength=Number(numbers[1].replace(/[^0-9]/g,''));
            if (!Number.isSafeInteger(byteLength) || byteLength.toLocaleString()!==numbers[1]) throw 0;
            const result={text:content,byteLength,sha256:digest[1]};return before?{state:'present',...result}:result;
        };
        const review=()=>{
            const p=panel(),views=p.querySelectorAll('.metadata-native-review');if (views.length!==1) throw 0;const view=views[0];
            const tables=view.querySelectorAll('.review-table'),details=[...view.querySelectorAll('.metadata-file-review')];
            if (tables.length!==1 || text(tables[0].querySelector('caption'))!=='Files in this review' || details.length!==ids.length || details.some(d=>!d.open)) throw 0;
            const inventory=[...tables[0].querySelectorAll('tbody > tr')];if (inventory.length!==ids.length) throw 0;
            if (text(view.querySelector(':scope > .save-note'))!=='No missing directories need to be created. Exact-preserved files keep their bytes, mode and identity. No file is deleted or renamed.') throw 0;
            return inventory.map((row,index)=>{
                show(row);const cells=row.querySelectorAll(':scope > td');if (cells.length!==3) throw 0;
                const path=text(row.querySelector(':scope > th code')),label=text(cells[0]);
                const action=label==='Preserve exact original'?'preserve':label==='Replace reviewed original'?'replace':label==='Create absent file'?'create':null;
                const detail=details[index],sides=detail.querySelectorAll('.metadata-raw-grid > .metadata-raw');
                if (!action || path!=='release/store/'+platform+'/en-US/'+ids[index] || sides.length!==2
                    || text(detail.querySelector('summary > code'))!==path || text(detail.querySelector('summary > .badge'))!==action) throw 0;
                const before=raw(sides[0],path,true),after=raw(sides[1],path,false);
                if (text(cells[1])!==`${before.state==='absent'?'Absent':before.byteLength+' bytes'} → ${after.byteLength} bytes`
                    || text(cells[2])!=='Unchanged') throw 0;
                return {id:ids[index],path,action,before,after,lineEndingsChanged:false};
            });
        };
        const outcome=()=>{
            const p=panel(),details=p.querySelectorAll('.metadata-outcome-details');if (details.length!==1) throw 0;
            if (!details[0].open) {const summary=details[0].querySelector(':scope > summary');show(summary);summary.click();}
            const facts=[...details[0].querySelectorAll('.save-outcome-facts > div')];if (facts.length!==4) throw 0;
            const labels=['Original project / locale','Effect / journal','Core / native resources','Reason'];
            const values=facts.map((row,index)=>{show(row);if (text(row.querySelector('dt'))!==labels[index]) throw 0;return text(row.querySelector('dd'));});
            return {title:text(p.querySelector('.section-heading h2')),project:values[0],effect:values[1],resources:values[2],reason:values[3]};
        };
        const confirmation=()=>{
            const dialogs=document.querySelectorAll('dialog');if (dialogs.length!==1 || !dialogs[0].classList.contains('metadata-confirm-dialog')
                || !dialogs[0].open || dialogs[0].querySelector('[role="alert"]')) throw 0;
            const dialog=dialogs[0],checks=dialog.querySelectorAll('.save-confirm-check input[type="checkbox"]');
            const inputs=dialog.querySelectorAll('.dialog-content > input'),buttons=dialog.querySelectorAll('.button-row > button');
            if (checks.length!==1 || inputs.length!==1 || buttons.length!==2 || checks[0].disabled || inputs[0].disabled || inputs[0].readOnly
                || inputs[0].type!=='text' || inputs[0].value.length>4 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing' || text(buttons[1])!=='Save text'
                || text(dialog.querySelector('.save-confirm-check'))!=='I reviewed all exact paths, full original/replacement text, digests and line-ending changes.') throw 0;
            return {dialog,check:checks[0],input:inputs[0],apply:buttons[1]};
        };
        const confirmationDisplay=()=>{
            const c=confirmation(),files=[...c.dialog.querySelectorAll('.metadata-confirm-files > li')];if (files.length!==ids.length) throw 0;
            const rows=files.map((row,index)=>{show(row);const path=text(row.querySelector('code')),match=/ — (create|replace|preserve)$/.exec(text(row));
                if (path!=='release/store/'+platform+'/en-US/'+ids[index] || !match || text(row)!==path+match[0]) throw 0;return [path,match[1]];});
            show(c.check);show(c.input);show(c.apply);
            return {title:text(c.dialog.querySelector('h2')),files:rows,checked:c.check.checked,typed:c.input.value,applyAvailable:!c.apply.disabled};
        };
    "#,&body,r#" } catch { return {state:'error'}; } })()"#].concat().replace("__ROUND__",&round.to_string()))
}



fn workflow_script(step:Step)->Option<String>{
    let body=match step {
        Step::Navigate=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');if(!b||b.disabled||document.querySelector('dialog'))throw 0;show(b);b.click();return {state:'ready'};"#.to_owned(),
        Step::Repository=>r#"if(!selected('GitHub')||!document.querySelector('form.github-form'))return {state:'wait'};const g=inputs(),button=document.querySelector('form.github-form button[type="submit"]');
            if(!button||text(button)!=='Preview GitHub setup'||!button.disabled||g.repository.value!==''||g.sha.value!==''||g.comparison.checked||document.querySelector('.github-proposal'))throw 0;
            show(g.repository);g.repository.focus();g.repository.select();if(document.activeElement!==g.repository||g.repository.selectionStart!==0||g.repository.selectionEnd!==0||!document.execCommand('insertText',false,'example/toolkit'))throw 0;return {state:'ready'};"#.to_owned(),
        Step::Pin=>r#"const g=inputs(),button=document.querySelector('form.github-form button[type="submit"]');if(!button||!button.disabled||g.repository.value!=='example/toolkit'||g.sha.value!==''||g.comparison.checked)throw 0;
            show(g.sha);g.sha.focus();g.sha.select();if(document.activeElement!==g.sha||g.sha.selectionStart!==0||g.sha.selectionEnd!==0||!document.execCommand('insertText',false,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))throw 0;return {state:'ready'};"#.to_owned(),
        Step::Propose=>r#"const g=inputs(),button=document.querySelector('form.github-form button[type="submit"]');if(!button||g.repository.value!=='example/toolkit'||g.sha.value!=='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'||g.comparison.checked||text(button)!=='Preview GitHub setup'||document.querySelector('.github-proposal'))throw 0;
            if(button.disabled)return {state:'wait'};remoteClosed();show(button);button.click();return {state:'ready'};"#.to_owned(),
        Step::Proposal=>r#"const g=inputs(),root=document.querySelector('.github-proposal'),button=document.querySelector('form.github-form button[type="submit"]');if(!root||!button||button.disabled)return {state:'wait'};
            const cards=[...root.children],rows=[...root.querySelectorAll('details.github-workflow')];if(cards.length!==3||cards.some(c=>!c.classList.contains('card'))||rows.length!==4)throw 0;remoteClosed();
            if(text(cards[0].querySelector('.badge'))!=='GitHub not contacted'||start(panel()).disabled)throw 0;
            const workflows=rows.map(row=>{const summary=row.querySelector(':scope > summary');show(summary);if(!row.open)summary.click();const pre=row.querySelector('pre'),path=text(row.querySelector('summary > code'));
                if(!pre||pre.getAttribute('aria-label')!=='Read-only proposed content for '+path)throw 0;show(pre);return {path,comparison:text(row.querySelector('summary > .badge')),content:text(pre.querySelector('code'))};});
            return {state:'ready',workflows,repository:g.repository.value,sha:g.sha.value,comparison:g.comparison.checked};"#.to_owned(),
        Step::Open(i) if i<3=>r#"const g=inputs(),p=panel(),b=start(p);if(g.repository.value!=='example/toolkit'||g.sha.value!=='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'||g.comparison.checked||document.querySelector('dialog'))throw 0;
            if(b.disabled)return {state:'wait'};remoteClosed();show(b);b.click();return {state:'ready'};"#.to_owned(),
        Step::OpenText(i) if i<3=>r#"const p=panel(),review=p.querySelector(':scope > .workflow-review');if(!review||text(p.querySelector('h2'))!=='Review the fresh native workflow plan')return {state:'wait'};
            const rows=[...review.querySelectorAll('details.github-workflow')];if(rows.length!==4||document.querySelector('dialog'))throw 0;for(const row of rows){const summary=row.querySelector(':scope > summary');show(summary);if(!row.open)summary.click();}return {state:'ready'};"#.to_owned(),
        Step::Review(i) if i<3=>r#"const p=panel(),review=p.querySelector(':scope > .workflow-review'),button=p.querySelector('.save-actions button.primary');if(!review||!button||button.disabled||text(p.querySelector('h2'))!=='Review the fresh native workflow plan')return {state:'wait'};
            if(document.querySelector('dialog'))throw 0;return {state:'ready',review:reviewDisplay(review)};"#.to_owned(),
        Step::CloseReview=>r#"const p=panel(),rows=[...p.querySelectorAll('.save-actions button')].filter(b=>text(b)==='Close workflow review / keep draft');if(rows.length!==1||rows[0].disabled||document.querySelector('dialog')||!p.querySelector(':scope > .workflow-review'))throw 0;remoteClosed();show(rows[0]);rows[0].click();return {state:'ready'};"#.to_owned(),
        Step::Confirm(i) if i==1||i==2=>format!(r#"const p=panel(),b=p.querySelector('.save-actions button.primary');if(!b||b.disabled||text(b)!=='{}'||document.querySelector('dialog'))throw 0;show(b);b.click();return {{state:'ready'}};"#,if i==1{"Confirm reviewed local files"}else{"Review unchanged confirmation"}),
        Step::Confirmation(i)|Step::Checked(i) if i==1||i==2=>r#"if(!document.querySelector('dialog.workflow-confirm-dialog[open]'))return {state:'wait'};return {state:'ready',confirmation:confirmationDisplay()};"#.to_owned(),
        Step::Check(i) if i==1||i==2=>r#"const c=confirmation();if(c.check.checked||!c.apply.disabled)throw 0;show(c.check);c.check.click();return {state:'ready'};"#.to_owned(),
        Step::Apply(i) if i==1||i==2=>r#"const c=confirmation();if(!c.check.checked||c.apply.disabled)throw 0;show(c.apply);c.apply.click();return {state:'ready'};"#.to_owned(),
        Step::Closed|Step::Result(1)|Step::Result(2)=>{
            let title=if step==Step::Result(1){"Reviewed local workflow bundle installed"}else{"Workflow review ended; configuration draft kept"};
            format!(r#"if(document.querySelector('dialog'))return {{state:'wait'}};const p=panel(),b=start(p),title=text(p.querySelector('h2'));if(title!=='{title}'||b.disabled||!p.querySelector('.save-outcome-facts'))return {{state:'wait'}};
                remoteClosed();if(p.querySelector('.workflow-conflict'))throw 0;const facts=[...p.querySelectorAll(':scope > .save-outcome-facts > div')].map(row=>{{show(row);return [text(row.querySelector('dt')),text(row.querySelector('dd'))];}});
                const close=[...p.querySelectorAll('.save-actions button')].filter(b=>['Close workflow review / keep draft','Request cancellation'].includes(text(b)));
                return {{state:'ready',title,facts,startAvailable:!b.disabled,applyAvailable:!!p.querySelector('.save-actions button.primary:not(:disabled)'),closeAvailable:close.some(b=>!b.disabled),hasReview:!!p.querySelector(':scope > .workflow-review'),conflict:null}};"#)
        },
        _=>return None,
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .native-workflow-panel .notice-danger')) throw 0;
        const text=e=>{{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0; return e.textContent;}};
        // Fixed create/preserve diffs only; current caller bodies1479/2303/3079/3816B.
        // The existing6038-unit per-diff and complete outer bounds stay unchanged.
        const diffText=e=>{{if (!e || typeof e.textContent!=='string' || e.textContent.length>6038) throw 0; return e.textContent;}};
        const visible=e=>{{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';}};
        const show=e=>{{if (!e) throw 0;e.scrollIntoView({{block:'center'}});if (!visible(e)) throw 0;}};
        const selected=label=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')===label);
        const panel=()=>{{const rows=document.querySelectorAll('section.native-workflow-panel');if (!selected('GitHub') || rows.length!==1) throw 0;return rows[0];}};
        const start=p=>{{const rows=p.querySelectorAll('button[aria-describedby="github-workflow-start-reason"]');
            if (rows.length!==1 || text(rows[0])!=='Review local workflow files') throw 0;return rows[0];}};
        const remoteClosed=()=>{{const rows=[...document.querySelectorAll('.github-disabled-actions button')];if (rows.length!==3 || rows.some(b=>!b.disabled)) throw 0;}};
        const inputs=()=>{{if (!selected('GitHub') || document.querySelector('dialog, .github-assertions')) throw 0;
            const forms=document.querySelectorAll('form.github-form');if (forms.length!==1) throw 0;const form=forms[0];
            const repository=form.querySelector('#github-toolkit-repository'),sha=form.querySelector('#github-toolkit-sha'),comparison=form.querySelector('.github-comparison-toggle input');
            if (!repository || !sha || !comparison || [repository,sha].some(i=>i.type!=='text' || i.disabled || i.readOnly)
                || repository.value.length>140 || sha.value.length>40 || text(form.querySelector('.github-draft > strong'))!=='local-github-apply · current draft') throw 0;
            return {{repository,sha,comparison}};}};
        const count=(raw,suffix)=>{{if (!raw.endsWith(suffix)) throw 0;const n=raw.slice(0,-suffix.length);
            if (!/^(?:[0-9]{{1,5}}|[0-9]{{1,2}},[0-9]{{3}})$/.test(n)) throw 0;return Number(n.replace(',',''));}};
        const cellText=cell=>[...cell.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join('');
        const inventory=root=>{{const tables=root.querySelectorAll('.workflow-files table');if (tables.length!==1) throw 0;
            const table=tables[0];if (text(table.querySelector('caption'))!=='Complete native workflow inventory — all four or refuse') throw 0;
            const rows=[...table.querySelectorAll('tbody > tr')];if (rows.length!==4) throw 0;
            return rows.map(row=>{{show(row);const cells=[...row.querySelectorAll(':scope > td')];if (cells.length!==3) throw 0;
                const label=text(cells[0]),action=label==='Create absent file'?'create':label==='Update canonical caller'?'update':label==='Preserve exact original'?'preserve':null;
                if (!action) throw 0;const absent=text(cells[1])==='Observed absent';
                return {{path:text(row.querySelector(':scope > th code')),action,
                    observed:absent?{{state:'absent'}}:{{state:'present',byteLength:count(cellText(cells[1]),' bytes'),sha256:text(cells[1].querySelector('code'))}},
                    generated:{{byteLength:count(cellText(cells[2]),' bytes'),sha256:text(cells[2].querySelector('code'))}}}};}});
        }};
        const reviewDisplay=review=>{{const rows=[...review.querySelectorAll('details.github-workflow')];if (rows.length!==4 || rows.some(row=>!row.open)) throw 0;
            const texts=rows.map(row=>{{const pre=row.querySelector('pre');show(pre);return {{path:text(row.querySelector('summary > code')),
                badge:text(row.querySelector('summary > .badge')),label:pre.getAttribute('aria-label'),content:diffText(pre.querySelector('code'))}};}});
            const facts=[...review.querySelectorAll(':scope > .github-facts > div')].map(row=>{{show(row);return [text(row.querySelector('dt')),text(row.querySelector('dd'))];}});
            return {{files:inventory(review),texts,basis:text(review.querySelector('.review-basis strong')),facts,
                note:text(review.querySelector(':scope > .save-note')),caution:text(review.querySelector(':scope > .review-caution'))}};
        }};
        const confirmation=()=>{{const dialogs=document.querySelectorAll('dialog');if (!selected('GitHub') || dialogs.length!==1) throw 0;
            const dialog=dialogs[0];if (!dialog.classList.contains('workflow-confirm-dialog') || !dialog.open || dialog.querySelector('[role="alert"]')) throw 0;
            const checks=dialog.querySelectorAll('.save-confirm-choice input[type="checkbox"]'),buttons=[...dialog.querySelectorAll('.button-row > button')];
            if (checks.length!==1 || checks[0].disabled || buttons.length!==2 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing'
                || !['Apply reviewed local files','Confirm unchanged plan'].includes(text(buttons[1]))
                || text(dialog.querySelector('.save-confirm-choice'))!=='I reviewed all four paths and complete before/after text. This only creates, updates or preserves local callers; it does not save configuration, contact GitHub or execute a release.') throw 0;
            return {{dialog,check:checks[0],keep:buttons[0],apply:buttons[1]}};}};
        const confirmationDisplay=()=>{{const c=confirmation(),p=c.dialog.querySelector('.dialog-content > p');
            const revision=/^This confirms the native plan made from draft revision ([0-9]{{1,10}}) and toolkit pin /.exec(text(p));if (!revision) throw 0;
            return {{title:text(c.dialog.querySelector('h2')),draftRevision:Number(revision[1]),pin:text(p.querySelector('code')),
                files:inventory(c.dialog),checked:c.check.checked,applyAvailable:!c.apply.disabled}};}};
        {body}
    }} catch {{ return {{state:'error'}}; }} }})()"#))
}


fn version_editor(edited:bool,saved:bool,reviewing:bool)->Value {
    let bytes=if saved{VERSION_AFTER}else{VERSION_BEFORE};
    json!({"title":"Edit saved version values","project":"Project: local-release-version. No automatic bump, trimming or numeric coercion.",
        "badge":"Separate native writer","selection":["Saved source: version.properties","Saved keys: VERSION_NAME and BUILD_NUMBER. iOS policy is disabled.",
            if saved{"Original values: 2.3.4 · Build 8. These may need policy correction."}else{"Original values: 1.2.3 · Build 7. These may need policy correction."}],
        "digests":[format!("Saved config: {} bytes · SHA256 {}",CONFIG.len(),digest(CONFIG)),format!("Saved source: {} bytes · SHA256 {}",bytes.len(),digest(bytes))],
        "values":{"name":if edited||saved{"2.3.4"}else{"1.2.3"},"build":if edited||saved{"8"}else{"7"}},
        "openAvailable":saved,"reviewLabel":"Validate and review values","reviewAvailable":!reviewing})
}
fn version_review_display()->Value {let view=version_view();json!({"title":"Edit only the two selected value spans","facts":[
    "version.properties — replace. Saved name key VERSION_NAME; build key BUILD_NUMBER. Saved iOS policy is disabled.",
    "Reviewed values: 2.3.4 · Build 8. Core format-valid only; Store acceptance and artifact agreement remain unknown.",
    "Unrelated bytes, spacing, quotes, comments, all separators and final-newline presence are preserved. No serializer or automatic version bump is used.",
    "Preserve original mode 0600.",
    "No parent directories will be created. Saved configuration and .gitignore are rechecked read-only dependencies.",
    "Complete bounded text, never a truncated diff. The browser may display separators similarly; the explicit styles, byte counts and native hashes describe the frozen bytes."],
    "before":view["file"]["before"],"after":view["file"]["after"]})}
fn version_result()->Value {json!({"title":"Submitted version values saved","submitted":"Submitted review: 2.3.4 · Build 8 · version.properties.",
    "facts":"Core effect: committed; journal: clean; native finality: settled. Reason: none."})}
fn version_readback(saved:bool)->Value {json!({"name":if saved{"2.3.4"}else{"1.2.3"},"build":if saved{"Build number 8"}else{"Build number 7"},
    "badge":"Observed from saved version file","source":"version.properties","sourceText":"Returned saved source:version.properties",
    "scope":"One non-atomic read. External changes are not continuously monitored. No artifact check or full preflight; release readiness is not assessed.",
    "config":"Saved config: release/mobile-release.json","readAvailable":true})}
fn metadata_result(round:usize)->Result<Value,()>{Ok(json!({"title":"Text saved","project":format!("local-metadata-text · {} / en-US",platform(round).ok_or(())?),
    "effect":"committed / clean","resources":"settled / settled","reason":"none"}))}
fn workflow_result(index:usize)->Value {json!({"state":"ready","title":if index==1{"Reviewed local workflow bundle installed"}else{"Workflow review ended; configuration draft kept"},
    "facts":[["Transaction effect",if index==1{"committed"}else{"not_started"}],["Journal",if index==1{"clean"}else{"not_created"}],
        ["Core resources","settled"],["Native finality","settled"]],"startAvailable":true,"applyAvailable":false,"closeAvailable":false,"hasReview":true,"conflict":null})}
fn next_changed(round:u8,after:Option<u8>)->Result<Step,()>{
    let found=fields(usize::from(round)).ok_or(())?.iter().enumerate().find(|(i,(_,old,new))|
        after.is_none_or(|n|*i>usize::from(n))&&old!=&Some(*new));
    Ok(found.map(|(i,_)|Step::Fill(round,i as u8)).unwrap_or(Step::Inputs(round)))
}
pub(super) enum Dom { Wait, Next(Step), Readback(usize,Step), Done }
impl Record {
    fn completed_original(&self,index:usize)->bool{self.sessions.get(index).is_some_and(|s|s.open_returned&&s.prepare_returned&&s.review_visible
        &&s.config_blocked&&s.finality.as_ref().is_some_and(|f|f.matches(&s.projection))
        &&(if self.case==Case::Workflow&&index==0{s.close_requested&&!s.apply_requested}else{s.apply_requested&&s.apply_returned&&s.acknowledged}))}
    pub(super) fn stale_ready(&self)->bool {self.case==Case::Workflow&&self.sessions.len()==3&&self.sessions[..2].iter().all(Session::complete)
        &&self.sessions[2].review_visible&&self.sessions[2].config_blocked&&live(&self.sessions[2].projection)&&!self.sessions[2].acknowledged}
    pub(super) fn readback_returned(&mut self,index:usize)->Result<(),()>{
        if !self.completed_original(index){return Err(());}let s=self.sessions.get_mut(index).ok_or(())?;
        if !s.visible||s.readback{return Err(());}s.readback=true;Ok(())
    }
    pub(super) fn dom(&mut self,step:Step,value:&Value)->Result<Dom,()>{
        let object=value.as_object().ok_or(())?;
        if value==&json!({"state":"wait"}){return Ok(Dom::Wait);}
        if value["state"]!="ready"{return Err(());}let simple=object.len()==1;
        let index=match step{Step::Context(i)|Step::Loaded(i)|Step::Load(i)|Step::Fill(i,_)|Step::Inputs(i)|Step::Validate(i)|Step::Validated(i)
            |Step::Open(i)|Step::Opened(i)|Step::Prepare(i)|Step::OpenText(i)|Step::Review(i)|Step::Confirm(i)|Step::Confirmation(i)|Step::Check(i)|Step::Checked(i)
            |Step::Type(i)|Step::Typed(i)|Step::Apply(i)|Step::Result(i)|Step::Refresh(i)|Step::Readback(i)=>usize::from(i),_=>0};
        if index>=self.case.sessions(){return Err(());}
        if matches!(step,Step::Result(_)|Step::Closed)&&!self.completed_original(index){return Ok(Dom::Wait);}
        let next=match (self.case,step) {
            (Case::Metadata,Step::Navigate)if simple=>Step::Load(0),
            (Case::Metadata,Step::Context(1))if simple=>Step::Load(1),
            (Case::Metadata,Step::Load(i))if simple=>Step::Loaded(i),
            (Case::Metadata,Step::Loaded(i))=>{
                if self.observations.len()!=index*2+1||self.passive_pending.is_some(){return Ok(Dom::Wait);}
                if object.len()!=2||value["display"]!=metadata_display(index,false,false,false)?{return Err(());}
                if index==1{self.selection_visible=true;}next_changed(i,None)?
            },
            (Case::Metadata,Step::Fill(i,n))if simple=>next_changed(i,Some(n))?,
            (Case::Metadata,Step::Inputs(i))=>{if object.len()!=2||value["display"]!=metadata_display(index,true,false,false)?{return Err(());}Step::Validate(i)},
            (Case::Metadata,Step::Validate(i))if simple=>Step::Validated(i),
            (Case::Metadata,Step::Validated(i))=>{
                if self.validations.len()!=index+1||self.validation_pending.is_some(){return Ok(Dom::Wait);}
                if object.len()!=2||value["display"]!=metadata_display(index,true,true,false)?{return Err(());}Step::Prepare(i)
            },
            (Case::Metadata,Step::Prepare(i))if simple=>Step::OpenText(i),
            (Case::Metadata,Step::OpenText(i))if simple=>Step::Review(i),
            (Case::Metadata,Step::Review(i))=>{
                if !self.sessions.get(index).is_some_and(|s|s.open_returned&&s.prepare_returned&&live(&s.projection)&&s.config_blocked){return Ok(Dom::Wait);}
                if object.len()!=3||value["review"]!=self.review(index)?||value["draft"]!=text_values(index).ok_or(())?{return Err(());}
                self.sessions[index].review_visible=true;Step::Confirm(i)
            },
            (Case::Version,Step::Navigate)if simple=>Step::Load(0),
            (Case::Version,Step::Load(0))if simple=>Step::Loaded(0),
            (Case::Version,Step::Loaded(0))=>{
                if self.observations.len()!=1||self.passive_pending.is_some(){return Ok(Dom::Wait);}
                if object.len()!=2||value["readback"]!=version_readback(false){return Err(());}Step::Open(0)
            },
            (Case::Version,Step::Open(0))if simple=>Step::Opened(0),
            (Case::Version,Step::Opened(0))=>{
                if !self.sessions.first().is_some_and(|s|s.open_returned&&s.projection["phase"]=="editing"&&s.config_blocked){return Ok(Dom::Wait);}
                self.check_checkout(0,&self.sessions[0].projection)?;
                if object.len()!=2||value["display"]!=version_editor(false,false,false){return Err(());}Step::Name
            },
            (Case::Version,Step::Name)if simple=>Step::Build,
            (Case::Version,Step::Build)if simple=>Step::Inputs(0),
            (Case::Version,Step::Inputs(0))=>{if object.len()!=2||value["display"]!=version_editor(true,false,false){return Err(());}Step::Prepare(0)},
            (Case::Version,Step::Prepare(0))if simple=>Step::Review(0),
            (Case::Version,Step::Review(0))=>{
                if !self.sessions.first().is_some_and(|s|s.open_returned&&s.prepare_returned&&live(&s.projection)&&s.config_blocked){return Ok(Dom::Wait);}
                self.review(0)?;
                if object.len()!=3||value["display"]!=version_editor(true,false,true)||value["review"]!=version_review_display(){return Err(());}
                self.sessions[0].review_visible=true;Step::Confirm(0)
            },
            (Case::Workflow,Step::Navigate)if simple=>Step::Repository,
            (Case::Workflow,Step::Repository)if simple=>Step::Pin,
            (Case::Workflow,Step::Pin)if simple=>Step::Propose,
            (Case::Workflow,Step::Propose)if simple=>Step::Proposal,
            (Case::Workflow,Step::Proposal)=>{
                let Some(proposal)=self.proposal.as_ref()else{return Ok(Dom::Wait);};
                let expected=proposal.as_array().ok_or(())?.iter().map(|r|json!({"path":r["path"],"comparison":"Not supplied · presence unknown","content":r["content"]})).collect::<Vec<_>>();
                if self.proposal_pending||object.len()!=5||value["workflows"]!=json!(expected)||value["repository"]!=REPOSITORY||value["sha"]!=PIN||value["comparison"]!=false{return Err(());}Step::Open(0)
            },
            (Case::Workflow,Step::Open(i))if simple=>Step::OpenText(i),
            (Case::Workflow,Step::OpenText(i))if simple=>Step::Review(i),
            (Case::Workflow,Step::Review(i))=>{
                if !self.sessions.get(index).is_some_and(|s|s.open_returned&&s.prepare_returned&&live(&s.projection)&&s.config_blocked){return Ok(Dom::Wait);}
                if object.len()!=2||value["review"]!=self.review(index)?{return Err(());}self.sessions[index].review_visible=true;
                match index{0=>Step::CloseReview,1=>Step::Confirm(1),2=>Step::Mutate,_=>return Err(())}
            },
            (Case::Workflow,Step::CloseReview)if simple=>Step::Closed,
            (Case::Workflow,Step::Closed)=>{
                if value!=&workflow_result(0){return Err(());}self.sessions[0].visible=true;return Ok(Dom::Readback(0,Step::Open(1)));
            },
            (_,Step::Confirm(i))if simple=>{
                let s=self.sessions.get_mut(index).ok_or(())?;if !s.review_visible||s.confirmation!=0||!live(&s.projection){return Err(());}s.confirmation=1;Step::Confirmation(i)
            },
            (_,Step::Confirmation(i)|Step::Checked(i)|Step::Typed(i))=>{
                let checked=!matches!(step,Step::Confirmation(_));let typed=matches!(step,Step::Typed(_));
                let s=self.sessions.get(index).ok_or(())?;
                if !s.review_visible||s.confirmation!=1||!live(&s.projection)||object.len()!=2{return Err(());}
                let expected=match self.case{
                    Case::Metadata=>json!({"title":"Save this reviewed locale bundle?","files":expected_metadata(index)?.as_array().ok_or(())?.iter().map(|f|json!([f["path"],f["action"]])).collect::<Vec<_>>(),"checked":checked,"typed":if typed{"SAVE"}else{""},"applyAvailable":typed}),
                    Case::Version=>json!({"title":"Save these reviewed version values?","selection":"Only version.properties, with marketing version 2.3.4 and build 8. The original configuration, ignore proof, source and parents must still match.",
                        "scope":"No configuration Save, native-project rewrite, build, Git/index operation, Store request or release is included. A submitted save may finish after cancellation.","checked":checked,"typed":if typed{"SAVE"}else{""},"applyAvailable":typed}),
                    Case::Workflow=>{if typed{return Err(());}json!({"title":if index==2{"Confirm four unchanged callers?"}else{"Apply this four-caller bundle?"},
                        "draftRevision":s.prepare.as_ref().ok_or(())?["draftRevision"],"pin":format!("{REPOSITORY}@{PIN}"),"files":self.review(index)?["files"],"checked":checked,"applyAvailable":checked})}
                };
                if value["confirmation"]!=expected{return Err(());}
                if typed||self.case==Case::Workflow&&checked{self.sessions[index].acknowledged=true;Step::Apply(i)}
                else if checked{Step::Type(i)}else{Step::Check(i)}
            },
            (_,Step::Check(i))if simple=>Step::Checked(i),
            (_,Step::Type(i))if simple&&self.case!=Case::Workflow=>Step::Typed(i),
            (_,Step::Apply(i))if simple=>Step::Result(i),
            (Case::Metadata,Step::Result(i))=>{
                if object.len()!=3||value["display"]!=metadata_display(index,true,true,true)?||value["outcome"]!=metadata_result(index)?{return Err(());}
                self.sessions[index].visible=true;return Ok(Dom::Readback(index,Step::Refresh(i)));
            },
            (Case::Version,Step::Result(0))=>{
                if object.len()!=3||value["display"]!=version_editor(true,true,false)||value["outcome"]!=version_result(){return Err(());}
                self.sessions[0].visible=true;return Ok(Dom::Readback(0,Step::Refresh(0)));
            },
            (Case::Workflow,Step::Result(i))if i==1||i==2=>{
                if value!=&workflow_result(index){return Err(());}self.sessions[index].visible=true;
                return Ok(Dom::Readback(index,if i==1{Step::Open(2)}else{Step::Done}));
            },
            (Case::Metadata,Step::Refresh(i))if simple=>Step::Readback(i),
            (Case::Version,Step::Refresh(0))if simple=>Step::Readback(0),
            (Case::Metadata,Step::Readback(i))=>{
                if self.observations.len()!=index*2+2||self.passive_pending.is_some(){return Ok(Dom::Wait);}
                if !self.sessions[index].complete()||object.len()!=3||value["display"]!=metadata_display(index,true,true,true)?||value["outcome"]!=metadata_result(index)?{return Err(());}
                if i==0{Step::Context(1)}else{Step::Done}
            },
            (Case::Version,Step::Readback(0))=>{
                if self.observations.len()!=2||self.passive_pending.is_some(){return Ok(Dom::Wait);}
                if !self.sessions[0].complete()||object.len()!=4||value["display"]!=version_editor(true,true,false)||value["outcome"]!=version_result()||value["readback"]!=version_readback(true){return Err(());}Step::Done
            },
            (_,Step::Done)if simple=>return Ok(Dom::Done),
            _=>return Err(()),
        };
        Ok(Dom::Next(next))
    }
}
pub(super) fn script(case:Case,step:Step)->Option<String>{
    if step==Step::Done{return Some("(() => ({state:'ready'}))()".into());}
    match case {
        Case::Metadata=>metadata_script(step),Case::Workflow=>workflow_script(step),
        Case::Version=>{
            if step==Step::Navigate{return Some(r#"(() => {try {const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Dashboard"]');if(!b||b.disabled||document.querySelector('dialog'))throw 0;const r=b.getBoundingClientRect(),s=getComputedStyle(b);if(!b.isConnected||r.width<=0||r.height<=0||s.display==='none'||s.visibility!=='visible')throw 0;b.click();return {state:'ready'};}catch{return {state:'error'};}})()"#.into());}
            let selected=match step{Step::Load(0)=>VersionStep::InitialLoad,Step::Loaded(0)=>VersionStep::InitialRead,Step::Open(0)=>VersionStep::Open(1),Step::Opened(0)=>VersionStep::ReadOpen(1),
                Step::Name=>VersionStep::Name(1),Step::Build=>VersionStep::Build(1),Step::Inputs(0)=>VersionStep::ReadInputs(1),Step::Prepare(0)=>VersionStep::Review(1),Step::Review(0)=>VersionStep::ReadReview(1),
                Step::Confirm(0)=>VersionStep::Confirm(1),Step::Confirmation(0)=>VersionStep::ReadConfirmation(1),Step::Check(0)=>VersionStep::Check(1),Step::Checked(0)=>VersionStep::ReadChecked(1),
                Step::Type(0)=>VersionStep::Type(1),Step::Typed(0)=>VersionStep::ReadTyped(1),Step::Apply(0)=>VersionStep::Apply(1),Step::Result(0)=>VersionStep::ReadSaved(1),
                Step::Refresh(0)=>VersionStep::Readback(1),Step::Readback(0)=>VersionStep::ReadReadback(1),_=>return None};version_script(selected)
        }
    }
}


// Inert finite regression bodies, also called from the existing observer DATA
// entry. They make no native/process/file originals and cannot mint Finality.
fn data_status(active: Value, revision: u64) -> Value {
    json!({"schemaVersion":1,"domain":workflow::DOMAIN,"windowGeneration":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "statusRevision":revision,"capability":{"available":true,"reason":"available"},"active":active,"lastTerminal":null})
}
fn data_opening() -> Value {
    json!({"domain":workflow::DOMAIN,"projectId":"fixed-public-project","sessionId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ownerGeneration":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phase":"opening","lateSettled":false,"conflict":null,"recovery":null,
        "applySubmitted":false,"checkout":null,"prepared":null,"nativeFinality":"pending","nativeReason":"none","coreOutcome":null,"reviewRemainingMs":null})
}
fn mismatched_or_out_of_order_original_is_refused() -> bool {
    let mut record=Record::new(Case::Workflow);
    let opening=data_opening();
    if record.status(data_status(opening.clone(),1),None,None).is_ok()
        ||record.status(data_status(Value::Null,0),None,None).is_err()
        ||record.open_request(0,"fixed-public-project").is_err()
        ||record.status(data_status(opening.clone(),1),Some("open"),None).is_err(){return false;}
    let mut foreign=opening.clone();foreign["sessionId"]=json!("cccccccccccccccccccccccccccccccc");
    if record.status(data_status(foreign,2),None,None).is_ok(){return false;}
    let mut wrong_generation=data_status(opening.clone(),2);wrong_generation["windowGeneration"]=json!("dddddddddddddddddddddddddddddddd");
    if record.status(wrong_generation,None,None).is_ok(){return false;}
    if record.status(data_status(opening.clone(),1),Some("open"),None).is_ok()
        ||record.status(data_status(opening.clone(),1),Some("prepare"),None).is_ok(){return false;}
    let mut editing=opening.clone();editing["phase"]=json!("editing");editing["checkout"]=json!({"revision":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"});
    if record.status(data_status(editing,2),None,None).is_err()
        ||record.status(data_status(opening,3),None,None).is_ok(){return false;}
    !record.sessions[0].complete()&&!record.completed_original(0)
}
fn incomplete_finality_cannot_finish_or_authorize_stale_append() -> bool {
    let mut record=Record::new(Case::Workflow);record.capability=true;record.config_blocked=true;
    for index in 0..3 {
        let mut projection=data_opening();projection["phase"]=json!(if index==2{"reviewing"}else{"final"});
        projection["reviewRemainingMs"]=json!(1000);projection["nativeFinality"]=json!(if index==2{"pending"}else{"settled"});
        // Even a full terminal-looking projection plus every renderer boolean
        // cannot replace the missing typed original. These are deliberately
        // NOT claimed to be valid native receipts.
        record.sessions.push(Session{projection,first_revision:1,open_returned:true,prepare:Some(json!({})),prepare_returned:true,
            review_visible:true,acknowledged:index==1,apply_requested:index==1,apply_returned:index==1,close_requested:index==0,
            confirmation:1,config_blocked:true,finality:None,readback:true,visible:true});
    }
    let fixture=Fixture{case:Case::Workflow,completed:3,stale:true,files:BTreeMap::new(),dirs:BTreeMap::new(),proposal:None};
    if record.sessions.iter().any(Session::complete)||record.completed_original(1)||record.stale_ready()
        ||record.readback_returned(1).is_ok()||record.report(&fixture).is_some(){return false;}
    matches!(record.dom(Step::Result(1),&workflow_result(1)),Ok(Dom::Wait))
}
pub(super) fn data_checks() -> bool {
    mismatched_or_out_of_order_original_is_refused() && incomplete_finality_cannot_finish_or_authorize_stale_append()
}
#[cfg(test)]
mod tests {
    #[test]
    fn mismatched_or_out_of_order_original_is_refused() { assert!(super::mismatched_or_out_of_order_original_is_refused()); }
    #[test]
    fn incomplete_finality_cannot_finish_or_authorize_stale_append() { assert!(super::incomplete_finality_cannot_finish_or_authorize_stale_append()); }
}
