//! One fixed synthetic session journey within the existing Windows observer.
//! Ordinary controls, existing native dialog originals and read-only document
//! projections only. There is no runtime selector, IPC injector or new owner.
use super::*;
use crate::asset_commands as input;
use crate::asset_session::{AssetStatus, windows_session_observation::WindowsSessionSnapshot};

pub(crate) enum Command { Status, Open, Context, Choose, Prepare, Delete, Commit, Bind, Discard, Lock }
impl Command { fn index(&self) -> usize { match self { Self::Status=>0,Self::Open=>1,Self::Context=>2,Self::Choose=>3,
    Self::Prepare=>4,Self::Delete=>5,Self::Commit=>6,Self::Bind=>7,Self::Discard=>8,Self::Lock=>9 } } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SessionStep { Navigate, Purpose, Open, Ready, Kind(u8), Replacement, Choose(u8), SetFile(u8), AcceptFile(u8),
    Chosen(u8), Fields(u8), Prepare(u8), Prepared(u8), Keep(u8), Kept(u8), Bind(u8), Bound(u8),
    Ios, IosReady, Delete, DeleteReady, ConfirmDelete, Deleted, Mutate, Dashboard, Reregister, SetProject, AcceptProject,
    Reregistered, LockPage, LockPrompt, Lock, Locked, Done }
fn choose_id(index: u8) -> Option<u32> { [2,6,10,14,18].get(usize::from(index)).copied() }
fn kind(index: u8) -> Option<&'static str> { match index { 0|1=>Some("android-keystore"),2=>Some("android-firebase"),3|4=>Some("ios-firebase"),_=>None } }
fn native_kind(index: u8) -> Option<DialogKind> {
    use native::ui::CredentialKind;
    Some(DialogKind::Credential(match index { 0|1=>CredentialKind::AndroidKeystore,2=>CredentialKind::AndroidFirebase,3|4=>CredentialKind::IosFirebase,_=>return None }))
}
fn expected_request(step: SessionStep, command: usize) -> Option<u8> { use SessionStep::*; Some(match (command, step) {
    (1,Open|Ready)|(2,Open|Ready)|(5,Delete|DeleteReady)|(9,Lock|Locked)=>1,
    (2,Ios|IosReady)=>2,
    (3,Choose(i)|SetFile(i)|AcceptFile(i)|Chosen(i)) if i<5=>i+1,
    (4,Prepare(i)|Prepared(i))|(6,Keep(i)|Kept(i))|(7,Bind(i)|Bound(i)) if i<4=>i+1,
    (6,ConfirmDelete|Deleted)=>5, _=>return None,
}) }
fn row_index(step: SessionStep) -> Option<u8> { use SessionStep::*; match step {
    Kind(i)|Choose(i)|SetFile(i)|AcceptFile(i)|Chosen(i)|Fields(i)|Prepare(i)|Prepared(i)|Keep(i)|Kept(i)|Bind(i)|Bound(i)=>Some(i),
    Replacement=>Some(1),_=>None,
} }

// A preview countdown is the sole clock-derived field in AssetStatus. Keep its
// positive, nonrenewing remainder separate; every other status field, revision,
// original Arc and private payload identity must survive a DOM wait unchanged.
fn status_projection(value: &Value) -> Option<(Value, Option<u32>)> {
    value["statusRevision"].as_u64().filter(|revision| *revision < u64::from(u32::MAX))?;
    let mut value = value.clone();
    let remaining = if let Some(preview) = value.get_mut("operation").and_then(|op| op.get_mut("preview")).filter(|value| !value.is_null()) {
        let remaining = u32::try_from(preview.get("expiresInMs")?.as_u64()?).ok()?;
        preview.as_object_mut()?.remove("expiresInMs"); Some(remaining)
    } else { None };
    Some((value, remaining))
}
struct ValidatedStep {
    step: SessionStep, status: Value, remaining: Option<u32>, next_operation: u32,
    owner: Option<Arc<OriginalWork>>, payloads: Vec<(String,u32,usize)>,
    source_started: bool, source_settled: bool, empty: bool,
}
impl ValidatedStep {
    fn capture(step: SessionStep, snapshot: &WindowsSessionSnapshot) -> Result<Self, ()> {
        let (status, remaining) = status_projection(&snapshot.status).ok_or(())?;
        if remaining == Some(0) { return Err(()); }
        Ok(Self { step, status, remaining, next_operation: snapshot.next_operation,
            owner: snapshot.owner.clone(), payloads: snapshot.payloads.clone(),
            source_started: snapshot.source_started, source_settled: snapshot.source_settled, empty: snapshot.empty })
    }
    fn matches(&mut self, step: SessionStep, snapshot: &WindowsSessionSnapshot) -> bool {
        let Some((status, remaining)) = status_projection(&snapshot.status) else { return false; };
        let matched = self.step == step && self.status == status && self.next_operation == snapshot.next_operation
            && match (&self.owner, &snapshot.owner) { (Some(a), Some(b)) => Arc::ptr_eq(a,b), (None,None) => true, _ => false }
            && match (self.remaining, remaining) { (Some(a),Some(b)) => b > 0 && b <= a, (None,None) => true, _ => false }
            && self.payloads == snapshot.payloads && self.source_started == snapshot.source_started
            && self.source_settled == snapshot.source_settled && self.empty == snapshot.empty;
        if matched { self.remaining = remaining; } matched
    }
}

pub(super) struct Record {
    pub(super) step: SessionStep, validated_step: Option<ValidatedStep>,
    requests: [u8;10], returns: [u8;10], inputs: [u8;10], status: Value,
    pub(super) originals: Vec<Arc<OriginalWork>>,
    records: [Option<(String,u32)>;3], payloads: Vec<(String,u32,usize)>, before_cancel: Option<(Value,Value)>,
    native_attempted: [[bool;2];5], native_returned: [[bool;2];5], native_settled: [bool;5],
    assessments: [bool;4], bound: [bool;4], context_revision: u32,
    replacement: bool, deleted: bool, mutation: bool, reregister_attempted: [bool;2], reregister_returned: [bool;2],
    pub(super) reregister_refused: bool, reregister_payloads: Vec<(String,u32,usize)>, locked: bool,
}
impl Record {
    pub(super) fn new() -> Self { Self { step:SessionStep::Navigate,validated_step:None,requests:[0;10],returns:[0;10],inputs:[0;10],status:Value::Null,
        originals:Vec::with_capacity(21),records:[None,None,None],payloads:Vec::new(),before_cancel:None,
        native_attempted:[[false;2];5],native_returned:[[false;2];5],native_settled:[false;5],assessments:[false;4],bound:[false;4],
        context_revision:0,replacement:false,deleted:false,mutation:false,reregister_attempted:[false;2],reregister_returned:[false;2],
        reregister_refused:false,reregister_payloads:Vec::new(),locked:false } }
    fn request(&mut self, command: Command) -> bool {
        let n=command.index();if n==0{return true;}
        let expected=expected_request(self.step,n);
        if expected.is_none() || self.requests[n].checked_add(1)!=expected || self.requests[n]!=self.returns[n] || self.requests[n]>=8{return false;}
        if n==2 && (self.requests[1]!=1 || self.returns[1]!=1) { return false; }
        self.requests[n]+=1;true
    }
    fn input(&mut self, command: Command) -> bool {
        let n=command.index();if self.inputs[n].checked_add(1)!=Some(self.requests[n]){return false;}self.inputs[n]+=1;true
    }
    fn returned(&self,n:usize)->bool{self.requests[n]>0&&self.requests[n]==self.returns[n]}
    fn result<E:serde::Serialize>(&mut self,command:Command,result:&Result<AssetStatus,E>)->bool{
        let n=command.index();if n==0{return true;}
        let Ok(status)=result else{return false;};let Ok(value)=serde_json::to_value(status) else{return false;};
        self.result_value(n,&value)
    }
    fn result_value(&mut self,n:usize,value:&Value)->bool{
        if n==0||n>=self.requests.len()||self.returns[n].checked_add(1)!=Some(self.requests[n]){return false;}
        if matches!(n,2|3|4|6|7)&&self.inputs[n]!=self.requests[n] || !self.status(value){return false;}
        self.returns[n]+=1;true
    }
    fn status(&mut self,value:&Value)->bool{
        if value["schemaVersion"]!=2 || !value["persistence"].is_null() || status_projection(value).is_none()
            || value["records"].as_array().is_none_or(|rows|rows.len()>3)
            || value["assignments"].as_array().is_none_or(|rows|rows.len()>3)
            || value["operation"]["settlement"].as_str().is_some_and(|v|matches!(v,"unknown"|"late-known")){return false;}
        if self.status["statusRevision"].as_u64().is_some_and(|old|value["statusRevision"].as_u64().is_some_and(|new|new<old)){return true;}
        self.status=value.clone();true
    }
    pub(super) fn observe(&mut self,snapshot:&WindowsSessionSnapshot)->Result<(),()>{
        if !self.status(&snapshot.status)||snapshot.next_operation>22||snapshot.payloads.len()>3{return Err(());}
        if let Some(owner)=&snapshot.owner{
            if owner.id as usize==self.originals.len()+1{
                if self.originals.len()>=21{return Err(());}self.originals.push(owner.clone());
            }else if !self.originals.last().is_some_and(|old|Arc::ptr_eq(old,owner)){return Err(());}
        }
        Ok(())
    }
    fn context(&self,ios:bool)->bool{
        self.status["mode"]=="session" && self.status["context"]["platform"]==if ios{"ios"}else{"android"}
            && self.status["context"]["stage"]=="candidate"&&self.status["context"]["purpose"]=="signing"
            && self.status["context"]["revision"]==self.context_revision
    }
    fn operation(&self,id:u32,kind:&str,phase:&str)->bool{
        let op=&self.status["operation"];op["operationId"]==id&&op["operation"]==kind&&op["phase"]==phase&&op["settlement"]=="known"
    }
    pub(super) fn ready(&mut self,snapshot:&WindowsSessionSnapshot,document:&DocumentBinding)->Result<bool,()>{
        self.observe(snapshot)?;use SessionStep::*;
        // A just-returning command can publish a later status after the relay
        // sampled the read-only document. Wait for that actual document instead
        // of combining its old payload identities with the newer command DATA.
        if self.status["statusRevision"] != snapshot.status["statusRevision"] { return Ok(false); }
        let settled=snapshot.owner_settled&&self.originals.iter().all(|owner|document.windows_original_settled(owner));
        let op=&self.status["operation"];
        if let Some(validated)=&mut self.validated_step {
            if !validated.matches(self.step,snapshot) { return Err(()); }
            return Ok(settled);
        }
        let ready=match self.step{
            Ready|IosReady=>{
                let expected=if self.step==Ready{1}else{2};
                if !self.returned(1)||!self.returned(2)||self.requests[2]!=expected{return Ok(false);}
                if self.status["context"]["revision"]!=expected{return Err(());}self.context_revision=expected as u32;
                settled&&self.context(expected==2)
            },
            Chosen(i)=>{
                if !self.returned(3)||!settled{return Ok(false);}
                let id=choose_id(i).ok_or(())?;let original=self.originals.iter().find(|owner|owner.id==id).ok_or(())?;
                let accepted=i!=4;
                if !self.native_returned[usize::from(i)][usize::from(accepted)]
                    || !document.windows_file_original_settled(original,accepted)
                    || op["operationId"]!=id||op["operation"]!="choose-file"||op["settlement"]!="known"
                    || !self.context(i>=3){return Err(());}
                if accepted{
                    if op["phase"]!="selected"||op["source"]!="captured"||op["reason"]!="none"
                        || op["selectionToken"].as_str().is_none_or(|token|!edit::token(token))
                        || !snapshot.source_started||!snapshot.source_settled{return Err(());}
                }else{
                    if op["phase"]!="idle"||op["source"]!="pending"||op["reason"]!="user-cancelled"
                        || !op["selectionToken"].is_null()||!op["assessment"].is_null()||!op["preview"].is_null()
                        || snapshot.source_started||snapshot.source_settled
                        || self.before_cancel.as_ref().is_none_or(|(records,assignments)|records!=&self.status["records"]||assignments!=&self.status["assignments"]){return Err(());}
                }
                self.native_settled[usize::from(i)]=true;true
            },
            Prepared(i)=>{
                if !self.returned(4)||!settled||op["phase"]!="preview"{return Ok(false);}
                if !self.operation(choose_id(i).ok_or(())?+1,"prepare","preview")||op["preview"]["action"]!="save"
                    || op["preview"]["subject"]["kind"].as_str()!=kind(i)||!assessment(&op["assessment"],i){return Err(());}
                self.assessments[usize::from(i)]=true;true
            },
            Kept(i)=>{
                if !self.returned(6)||!settled||op["phase"]!="preview"{return Ok(false);}
                let slot=if i<2{0}else{usize::from(i)-1};let revision=if i==1{2}else{1};
                let id=op["preview"]["subject"]["recordId"].as_str().filter(|id|edit::token(id)).ok_or(())?;
                if !self.operation(choose_id(i).ok_or(())?+2,"commit","preview")||op["preview"]["action"]!="bind"
                    || op["preview"]["subject"]["recordRevision"]!=revision||op["preview"]["subject"]["kind"].as_str()!=kind(i)
                    || snapshot.payloads.len()!=slot+1||snapshot.payloads[slot].0!=id||snapshot.payloads[slot].1!=revision{return Err(());}
                if i==1{
                    if self.records[0].as_ref().is_none_or(|(old,rev)|old!=id||*rev!=1)||self.payloads.len()!=1
                        || snapshot.payloads[0].2==self.payloads[0].2{return Err(());}self.replacement=true;
                }else if self.records.iter().flatten().any(|(old,_)|old==id){return Err(());}
                self.records[slot]=Some((id.into(),revision));self.payloads=snapshot.payloads.clone();true
            },
            Bound(i)=>{
                if !self.returned(7)||!settled||op["phase"]!="idle"{return Ok(false);}
                let slot=if i<2{0}else{usize::from(i)-1};let(id,revision)=self.records[slot].as_ref().ok_or(())?;
                if !self.operation(choose_id(i).ok_or(())?+3,"bind","idle")||snapshot.payloads!=self.payloads
                    || self.status["assignments"].as_array().ok_or(())?.iter().filter(|row|row["recordId"].as_str()==Some(id.as_str())
                        && row["recordRevision"]==*revision&&row["contextRevision"]==self.context_revision&&row["kind"].as_str()==kind(i)
                        && row["availability"]=="available").count()!=1{return Err(());}
                self.bound[usize::from(i)]=true;true
            },
            DeleteReady=>{
                if !self.returned(5)||!settled||op["phase"]!="preview"{return Ok(false);}
                let(id,revision)=self.records[1].as_ref().ok_or(())?;
                if !self.operation(19,"prepare-delete","preview")||op["preview"]["action"]!="delete"
                    || op["preview"]["subject"]["recordId"].as_str()!=Some(id.as_str())||op["preview"]["subject"]["recordRevision"]!=*revision{return Err(());}true
            },
            Deleted=>{
                if !self.returned(6)||!settled||op["phase"]!="idle"{return Ok(false);}
                let expected=vec![self.payloads.first().ok_or(())?.clone(),self.payloads.get(2).ok_or(())?.clone()];
                if !self.operation(20,"commit","idle")||snapshot.payloads!=expected{return Err(());}
                self.payloads=expected;self.deleted=true;true
            },
            Reregistered=>{
                if !self.reregister_refused||!settled{return Ok(false);}
                if !self.operation(21,"choose-project","idle")||op["reason"]!="exclusion-unconfirmed"
                    || snapshot.payloads!=self.reregister_payloads||snapshot.payloads!=self.payloads{return Err(());}true
            },
            Locked=>{
                if !self.returned(9)||!settled||!snapshot.empty{return Ok(false);}
                // Lock retires the current original; it does not allocate an
                // operation or substitute a new coordinator/source receipt.
                if !self.operation(21,"lock","idle")||op["reason"]!="exclusion-unconfirmed"||!snapshot.payloads.is_empty(){return Err(());}
                self.locked=true;true
            },
            Mutate|SetFile(_)|AcceptFile(_)|SetProject|AcceptProject|Done=>false,
            _=>settled,
        }; if ready{self.validated_step=Some(ValidatedStep::capture(self.step,snapshot)?);}Ok(ready)
    }
    pub(super) fn script(&mut self)->Option<String>{
        use SessionStep::*;
        if self.step==Choose(4){self.before_cancel=Some((self.status["records"].clone(),self.status["assignments"].clone()));}
        let body:String=match self.step{
            Navigate|LockPage=>"return nav('Credentials');".into(),Purpose=>"return selectValue('Input purpose','signing');".into(),
            Open=>"return click('Start session — keep inputs in memory');".into(),
            Ready|IosReady=>"const p=panel();if(!text(p).includes('Context submitted · not yet policy-validated'))return wait();return ready();".into(),
            Kind(i)=>format!("return selectValue('What would you like to provide?',{});",serde_json::to_string(kind(i)?).ok()?),
            Replacement=>"return selectReplacement();".into(),Choose(_)=>"return click('Select file…');".into(),
            Chosen(i) if i<4=>"const f=panel().querySelector('form.session-inputs');if(!f)return wait();show(f);return ready();".into(),
            Reregistered=>"const title=document.querySelector('.project-identity h2');if(!title||text(title)!=='project')return wait();show(title);return ready();".into(),
            Chosen(_)|Deleted=>"const p=panel(),s=p.querySelector('.session-progress');if(!s||text(s.querySelector('.badge'))!=='idle'||p.querySelector('[aria-label=\"Explicit private-input review\"]'))return wait();return ready();".into(),
            Fields(i) if i<2=>r#"const f=panel().querySelector('form.session-inputs');if(!f)return wait();const fields=[...f.querySelectorAll('input')];if(fields.length!==3)throw 0;
                const values=[['storePassword','fictional-store-password'],['keyAlias','fixture_alias'],['keyPassword','fictional-key-password']];
                if(fields.some(i=>i.disabled))return wait();for(const [name,value] of values){const found=fields.filter(i=>i.id.endsWith('-'+name));if(found.length!==1||found[0].type!=='password'||found[0].autocomplete!=='new-password'||found[0].readOnly)throw 0;
                    const i=found[0];show(f);i.focus();i.select();if(!document.execCommand('insertText',false,value))throw 0;}return ready();"#.into(),
            Prepare(_)=>"return click('Prepare private review',panel().querySelector('form.session-inputs'));".into(),
            Prepared(_)=>"return reviewReady('Keep for this session');".into(),Kept(_)=>"return reviewReady('Assign to this context');".into(),
            Keep(_)=>"return click('Keep for this session',review());".into(),Bind(_)=>"return click('Assign to this context',review());".into(),
            Bound(i)=>format!("const rows=panel().querySelectorAll('.session-records article');if(rows.length!=={})return wait();const row=rows[{}];if(text(row.querySelector('.badge'))!=='Assigned to current submitted context')return wait();show(row);return ready();",if i<2{1}else{i},if i<2{0}else{i-1}),
            Ios=>"return selectValue('Platform','ios');".into(),
            Delete=>"const rows=panel().querySelectorAll('.session-records article');if(rows.length!==3)return wait();if(!text(rows[1]).includes('Revision 1'))throw 0;return click('Review removal…',rows[1]);".into(),
            DeleteReady=>"return reviewReady('Remove session copy');".into(),ConfirmDelete=>"return click('Remove session copy',review());".into(),
            Dashboard=>"return nav('Dashboard');".into(),
            Reregister=>"const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Open another project');if(!b||b.disabled)return wait();show(b);b.click();return ready();".into(),
            LockPrompt=>"return click('Discard session…');".into(),Lock=>"return click('Discard session copies',panel().querySelector('[aria-label=\"Confirm private-input lock\"]'));".into(),
            Locked=>"const p=panel();if(p.querySelector('.session-records')||!button('Start session — keep inputs in memory',p))return wait();return ready();".into(),
            _=>return None,
        };
        Some(format!(r#"(()=>{{try{{'use strict';
            const text=e=>(e?.textContent??'').trim().replace(/\s+/g,' '),wait=()=>({{state:'wait'}}),ready=()=>({{state:'ready'}});
            const show=e=>{{if(!e||!e.isConnected)throw 0;e.scrollIntoView({{block:'center'}});const r=e.getBoundingClientRect();if(!r||r.width<=0||r.height<=0)throw 0;}};
            const button=(label,root=document)=>[...root.querySelectorAll('button')].find(b=>text(b)===label);
            const panel=()=>{{const p=document.querySelectorAll('.credential-session');if(p.length!==1)throw 0;return p[0];}};
            const review=()=>panel().querySelector('[aria-label="Explicit private-input review"]');
            const click=(label,root)=>{{if(root===null)return wait();const b=button(label,root??panel());if(!b||b.disabled)return wait();show(b);b.click();return ready();}};
            const nav=label=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+label+'"]');if(!b||b.disabled)return wait();show(b);b.click();return ready();}};
            const select=(label)=>{{const labels=[...panel().querySelectorAll('label')].filter(l=>text(l)===label);if(labels.length!==1)return null;const s=document.getElementById(labels[0].htmlFor);if(!(s instanceof HTMLSelectElement)||s.disabled)return null;return s;}};
            const selectValue=(label,value)=>{{const s=select(label);if(!s)return wait();const choices=[...s.options].flatMap((o,i)=>o.value===value?[i]:[]);if(choices.length!==1||s.options[choices[0]].disabled)throw 0;show(s);if(s.selectedIndex!==choices[0]){{s.focus();s.selectedIndex=choices[0];s.dispatchEvent(new Event('change',{{bubbles:true}}));}}return ready();}};
            const selectReplacement=()=>{{const s=select('New or replacement copy?');if(!s)return wait();if(s.options.length!==2||!text(s.options[1]).includes('Replace item 1')||!text(s.options[1]).includes('revision 1'))throw 0;show(s);s.focus();s.selectedIndex=1;s.dispatchEvent(new Event('change',{{bubbles:true}}));return ready();}};
            const reviewReady=label=>{{const r=review();if(!r)return wait();const b=button(label,r);if(!b||b.disabled)return wait();show(r);return ready();}};
            {body}
        }}catch{{return {{state:'error'}}}}}})()"#))
    }
    pub(super) fn dom_returned(&mut self)->Result<(),()>{use SessionStep::*;self.validated_step=None;self.step=match self.step{
        Navigate=>Purpose,Purpose=>Open,Open=>Ready,Ready=>Kind(0),Kind(1)=>Replacement,Kind(i)=>Choose(i),Replacement=>Choose(1),
        Choose(i)=>SetFile(i),Chosen(i) if i<2=>Fields(i),Chosen(i) if i<4=>Prepare(i),Chosen(4)=>Delete,
        Fields(i)=>Prepare(i),Prepare(i)=>Prepared(i),Prepared(i)=>Keep(i),Keep(i)=>Kept(i),Kept(i)=>Bind(i),Bind(i)=>Bound(i),
        Bound(0)=>Kind(1),Bound(1)=>Kind(2),Bound(2)=>Ios,Bound(3)=>Kind(4),Ios=>IosReady,IosReady=>Kind(3),
        Delete=>DeleteReady,DeleteReady=>ConfirmDelete,ConfirmDelete=>Deleted,Deleted=>Mutate,
        Dashboard=>Reregister,Reregister=>SetProject,Reregistered=>LockPage,LockPage=>LockPrompt,LockPrompt=>Lock,Lock=>Locked,Locked=>Done,
        _=>return Err(()),};Ok(())}
    pub(super) fn native_spec(&self)->Option<(u32,DialogKind,Option<usize>,bool)>{use SessionStep::*;match self.step{
        SetFile(i)=>Some((choose_id(i)?,native_kind(i)?,(i!=4).then_some(usize::from(i)),false)),
        AcceptFile(i)=>Some((choose_id(i)?,native_kind(i)?,None,true)),
        SetProject=>Some((21,DialogKind::Project,None,false)),AcceptProject=>Some((21,DialogKind::Project,None,true)),_=>None,
    }}
    pub(super) fn native_attempt(&mut self)->bool{use SessionStep::*;let slot=match self.step{
        SetFile(i)=>&mut self.native_attempted[usize::from(i)][0],AcceptFile(i)=>&mut self.native_attempted[usize::from(i)][1],
        SetProject=>&mut self.reregister_attempted[0],AcceptProject=>&mut self.reregister_attempted[1],_=>return false,
    };if *slot{return false;}*slot=true;true}
    pub(super) fn native_done(&mut self)->Result<(),()>{use SessionStep::*;self.validated_step=None;self.step=match self.step{
        SetFile(i)=>{self.native_returned[usize::from(i)][0]=true;if i==4{Chosen(i)}else{AcceptFile(i)}},
        AcceptFile(i)=>{self.native_returned[usize::from(i)][1]=true;Chosen(i)},
        SetProject=>{self.reregister_returned[0]=true;AcceptProject},AcceptProject=>{self.reregister_returned[1]=true;Reregistered},_=>return Err(()),};Ok(())}
    pub(super) fn mutation_due(&self)->bool{self.step==SessionStep::Mutate&&!self.mutation&&self.deleted&&self.replacement}
    pub(super) fn mutated(&mut self)->Result<(),()>{if !self.mutation_due(){return Err(());}self.mutation=true;self.validated_step=None;self.reregister_payloads=self.payloads.clone();self.step=SessionStep::Dashboard;Ok(())}
    pub(super) fn reregister_result(&mut self,result:&Result<Option<Project>,AssetError>)->bool{
        if !matches!(self.step,SessionStep::AcceptProject|SessionStep::Reregistered)||self.reregister_refused
            || !self.reregister_attempted[1]||!matches!(result,Err(error) if error.reason==Reason::ExclusionUnconfirmed){return false;}
        self.reregister_refused=true;true
    }
    pub(super) fn complete(&self,document:&DocumentBinding,quit:&Arc<OriginalWork>)->bool{
        self.step==SessionStep::Done&&self.native_settled==[true;5]&&self.assessments==[true;4]&&self.bound==[true;4]
            &&self.replacement&&self.deleted&&self.mutation&&self.reregister_refused&&self.reregister_returned==[true;2]&&self.locked
            &&self.requests==[0,1,2,5,4,1,5,4,0,1]&&self.returns==self.requests
            &&self.inputs==[0,0,2,5,4,0,5,4,0,0]&&self.originals.len()==21
            &&document.windows_session_final(&self.originals,quit)
    }
}
fn assessment(value:&Value,index:u8)->bool{
    let firebase=index>=2;let Some(expected)=kind(index) else{return false;};
    let state=if firebase{"format-valid"}else{"configured"};let identity=if firebase{"match"}else{"not-applicable"};
    if value["schemaVersion"]!=1||value["policyVersion"]!=input::POLICY||value["kind"]!=expected
        ||value["state"]!=state||value["identity"]!=identity||value["context"]!=json!({"platform":if index==3{"ios"}else{"android"},"stage":"candidate","purpose":"signing"})
        ||value["applicability"]!=json!({"state":"required","reason":"selected"}){return false;}
    let Some(fields)=value["fields"].as_array()else{return false;};
    if fields.len()!=if firebase{1}else{4}||fields.iter().any(|field|field["presence"]!="supplied"||field["state"]!=state||field["issues"].as_array().is_none_or(|issues|!issues.is_empty())){return false;}
    let scopes=fields.iter().flat_map(|field|field["checks"].as_array().into_iter().flatten()).map(|check|(check["scope"].as_str(),check["outcome"].as_str())).collect::<Vec<_>>();
    let expected:&[(&str,&str)]=match index{
        0|1=>&[("jks-header","asserted-pass"),("value-admission","passed"),("value-admission","passed"),("value-admission","passed")],
        2=>&[("json-document","asserted-pass"),("firebase-shape","passed"),("application-identity","passed")],
        3=>&[("plist-document","asserted-pass"),("firebase-shape","passed"),("application-identity","passed")],_=>return false,
    };
    let assurance=&value["assurance"];
    scopes==expected.iter().map(|(scope,outcome)|(Some(*scope),Some(*outcome))).collect::<Vec<_>>()
        &&assurance["basis"]=="supplied-input-only"&&assurance["nativeValidation"]=="not-run"&&assurance["serviceValidation"]=="not-run"
        &&assurance["releaseReadiness"]=="unknown"&&assurance["sourceCustody"]=="not-established"
        &&["selectedFilesRead","keyringAccessed","storageWritesPerformed","projectCodeExecuted"].iter().all(|key|assurance[*key]==false)
}

impl Observation{
    pub(in crate::shell) fn session_request(&self,command:Command){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        if !self.timely()||!r.credentials.as_mut().is_some_and(|s|s.request(command)){self.fail(Refusal::CredentialRequest);}}
    pub(in crate::shell) fn session_result(&self,command:Command,result:&Result<AssetStatus,AssetError>){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        if !self.timely()||!r.credentials.as_mut().is_some_and(|s|s.result(command,result)){self.fail(Refusal::CredentialResult);}}
    pub(in crate::shell) fn session_prepare_result(&self,result:&Result<AssetStatus,input::CommandError>){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        if !self.timely()||!r.credentials.as_mut().is_some_and(|s|s.result(Command::Prepare,result)){self.fail(Refusal::CredentialResult);}}
    pub(in crate::shell) fn session_context_input(&self,args:&input::Context<'_>){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        let project=r.project.as_ref().map(|p|p.id.clone());let Some(s)=r.credentials.as_mut()else{self.fail(Refusal::CredentialRequest);return;};
        let ios=matches!(s.step,SessionStep::Ios|SessionStep::IosReady);
        if project.as_deref()!=Some(args.project_id)||args.draft!=&self.base||args.platform!=if ios{input::Platform::Ios}else{input::Platform::Android}
            ||args.stage!=input::Stage::Candidate||args.purpose!=input::Purpose::Signing||!s.input(Command::Context){self.fail(Refusal::CredentialRequest);}}
    pub(in crate::shell) fn session_choose_input(&self,args:&input::Choose<'_>){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        let Some(s)=r.credentials.as_mut()else{self.fail(Refusal::CredentialRequest);return;};let Some(i)=row_index(s.step)else{self.fail(Refusal::CredentialRequest);return;};
        let replacement=if i==1{args.replacement.as_ref().is_some_and(|actual|s.records[0].as_ref().is_some_and(|(id,revision)|id==actual.record_id&&*revision==actual.expected_revision))}else{args.replacement.is_none()};
        if kind(i)!=Some(args.kind.name())||args.context_revision!=s.context_revision||!replacement||!s.input(Command::Choose){self.fail(Refusal::CredentialRequest);}}
    pub(in crate::shell) fn session_prepare_input(&self,args:&input::Prepare<'_>){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        let Some(s)=r.credentials.as_mut()else{self.fail(Refusal::CredentialRequest);return;};let Some(i)=row_index(s.step)else{self.fail(Refusal::CredentialRequest);return;};
        let fields=if i<2{json!({"storePassword":"fictional-store-password","keyAlias":"fixture_alias","keyPassword":"fictional-key-password"})}else{json!({})};
        let source=matches!(&args.source,input::Source::Selection(token) if s.status["operation"]["selectionToken"].as_str()==Some(*token));
        if !matches!(s.step,SessionStep::Prepare(_)|SessionStep::Prepared(_))||!source||args.fields!=Some(&fields)||args.label.is_some()
            ||args.context_revision!=s.context_revision||!s.input(Command::Prepare){self.fail(Refusal::CredentialRequest);}}
    pub(in crate::shell) fn session_confirmation_input(&self,token:&str,bind:bool){if self.case!=Case::CredentialSession{return;}let Some(mut r)=self.record()else{return;};
        let Some(s)=r.credentials.as_mut()else{self.fail(Refusal::CredentialRequest);return;};let action=if bind{"bind"}else if matches!(s.step,SessionStep::ConfirmDelete|SessionStep::Deleted){"delete"}else{"save"};
        if s.status["operation"]["preview"]["token"].as_str()!=Some(token)||s.status["operation"]["preview"]["action"]!=action
            ||!s.input(if bind{Command::Bind}else{Command::Commit}){self.fail(Refusal::CredentialRequest);}}
}


impl Observation {
    pub(super) fn credential_tick(self:&Arc<Self>,app:&tauri::AppHandle) {
        if self.case!=Case::CredentialSession||std::thread::current().id()==self.main||!self.timely(){self.fail(Refusal::CredentialTick);return;}
        let state=app.state::<super::super::ShellState>();
        let snapshot=match state.document.windows_session_snapshot(){
            Ok(Some(snapshot))=>snapshot,Ok(None)=>return,Err(())=>{self.fail(Refusal::CredentialTick);return;},
        };
        let (mutation,dispatch,script)={
            let Some(mut r)=self.record()else{return;};
            if r.step!=Step::Credential||r.pending.is_some(){self.fail(Refusal::CredentialTick);return;}
            let Some(session)=r.credentials.as_mut()else{self.fail(Refusal::CredentialTick);return;};
            if session.observe(&snapshot).is_err(){self.fail(Refusal::CredentialTick);return;}
            if session.step==SessionStep::Done{r.step=Step::Close;return;}
            if session.native_spec().is_some(){r.pending=Some(Pending::Native(Step::Credential));return;}
            if session.mutation_due(){
                if !snapshot.owner_settled||!session.originals.iter().all(|owner|state.document.windows_original_settled(owner)){
                    self.fail(Refusal::CredentialTick);return;
                }
                r.pending=Some(Pending::Fixture);(true,None,None)
            }else{
                match session.ready(&snapshot,&state.document){Ok(false)=>return,Err(())=>{self.fail(Refusal::CredentialTick);return;},Ok(true)=>{}}
                let Some(script)=session.script()else{self.fail(Refusal::CredentialTick);return;};
                if r.evaluations==DOM_LIMIT{self.fail(Refusal::CredentialTick);return;}
                r.evaluations+=1;let dispatch=DomDispatch{step:Step::Credential,sequence:r.evaluations};
                r.pending=Some(Pending::Dom(dispatch));(false,Some(dispatch),Some(script))
            }
        };
        if mutation {
            // The ordinary relay has already reserved this one fixed action.
            // No Record or source/GUI callback guard crosses the native writer.
            let result=match self.credential_fixture.try_lock(){
                Ok(mut fixture)=>fixture.as_mut().ok_or(()).and_then(|fixture|fixture.mutate_original_once().map_err(|_|())),Err(_)=>Err(()),
            };
            let Some(mut r)=self.record()else{return;};
            if r.pending!=Some(Pending::Fixture)||r.step!=Step::Credential{self.fail(Refusal::CredentialFixture);return;}
            r.pending=None;
            if result.is_err()||!self.timely()||!r.credentials.as_mut().is_some_and(|session|session.mutated().is_ok()){
                self.fail(Refusal::CredentialFixture);
            }
            return;
        }
        let(Some(dispatch),Some(script))=(dispatch,script)else{self.fail(Refusal::CredentialTick);return;};
        let Some(window)=app.get_webview_window(super::super::MAIN_WINDOW)else{self.fail(Refusal::CredentialTick);return;};
        let original=self.clone();
        // Existing synchronous callback gate, not a second executor. A possibly
        // effectful callback is never retried until its original body returned.
        if !self.timely()||window.eval_with_callback(script,move|value|original.dom(dispatch,&value)).is_err(){self.fail(Refusal::CredentialTick);}
    }
    pub(super) fn credential_native_step(&self,id:u32,kind:DialogKind,call:&Arc<GuiCall>){
        if self.case!=Case::CredentialSession||std::thread::current().id()!=self.main||!self.timely(){self.fail(Refusal::NativeStep);return;}
        let result=self.credential_native_body(id,kind,call);
        if result==Ok(None){return;}
        if let Err(reason)=result{self.fail(reason);}
        let Some(mut r)=self.record()else{return;};
        if r.step!=Step::Credential||r.pending!=Some(Pending::Native(Step::Credential)){self.fail(Refusal::NativeStep);return;}
        r.pending=None;
        if result==Ok(Some(true))&&self.timely()&&!r.credentials.as_mut().is_some_and(|session|session.native_done().is_ok()){
            self.fail(Refusal::NativeStep);
        }
    }
    fn credential_native_body(&self,id:u32,kind:DialogKind,call:&Arc<GuiCall>)->Result<Option<bool>,Refusal>{
        let Some(dialog)=observed_dialog().map_err(|_|Refusal::NativePrecondition)?else{return Ok(Some(false));};
        let Some(mut r)=self.try_record()else{return Ok(None);};
        let(expected_id,expected_kind,index,accept)=r.credentials.as_ref().and_then(Record::native_spec).ok_or(Refusal::NativePrecondition)?;
        if r.pending!=Some(Pending::Native(Step::Credential))||r.step!=Step::Credential||id!=expected_id||kind!=expected_kind
            ||dialog.id!=id||dialog.native.kind!=kind||!Arc::ptr_eq(call,&dialog.call)
            ||dialog.native.stopped||dialog.native.close_entered||dialog.native.show_returned||dialog.native.settled||dialog.native.response.is_some()
            ||!self.timely(){return Err(Refusal::NativePrecondition);}
        let owner=dialog.call.owner().ok_or(Refusal::NativePrecondition)?;
        if owner.id!=id||owner.interrupted()||!Arc::ptr_eq(&owner.gui,call)
            ||!r.credentials.as_ref().is_some_and(|session|session.originals.iter().any(|original|Arc::ptr_eq(original,&owner)))
            ||!call.facts().is_some_and(|g|g.dispatched&&!g.not_created&&!g.response&&!g.accepted&&!g.declined&&g.refusal.is_none()
                &&!g.close_queued&&!g.close_ack&&!g.release_queued&&!g.released){return Err(Refusal::NativePrecondition);}
        if let Some(witness)=r.dialogs.iter().find(|witness|witness.id==id){if !witness.same(&dialog){return Err(Refusal::NativePrecondition);}}
        else{
            if r.dialogs.len()>=8||[1,2,6,10,14,18,21,22].get(r.dialogs.len()).copied()!=Some(id){return Err(Refusal::NativePrecondition);}
            r.dialogs.push(DialogWitness{id,kind,call:call.clone(),owner});
        }
        let visible_at=r.dialogs.iter().position(|witness|witness.id==id).ok_or(Refusal::NativePrecondition)?;
        if !dialog.native.created||!dialog.native.showing||!dialog.native.visible||!dialog.native.presented{
            return if r.visible[visible_at]{Err(Refusal::NativePrecondition)}else{Ok(Some(false))};
        }
        if !dialog.native.callbacks_active||!dialog.native.observation_turn||!dialog.action_allowed
            ||!call.facts().is_some_and(|g|g.dispatched&&g.created&&!g.constructing&&g.showing&&!g.not_created
                &&!g.response&&!g.accepted&&!g.declined&&g.selected.is_none()&&g.refusal.is_none()&&!g.destroyed&&!g.released){return Err(Refusal::NativePrecondition);}
        r.visible[visible_at]=true;
        if accept&&!dialog.native.folder_navigation_observed{return Ok(Some(false));}
        let target=match index{
            Some(index)=>{
                let fixture=self.credential_fixture.try_lock().map_err(|_|Refusal::NativePrecondition)?;
                Some(fixture.as_ref().ok_or(Refusal::NativePrecondition)?.path(index).map_err(|_|Refusal::NativePrecondition)?)
            },None if kind==DialogKind::Project&&!accept=>Some(self.project_path.clone()),_=>None,
        };
        let action=if accept{DialogAction::Accept}else if kind==DialogKind::Project{
            DialogAction::ChooseFolder(target.as_deref().ok_or(Refusal::NativePrecondition)?)
        }else if let Some(path)=target.as_deref(){DialogAction::ChooseFile(path)}else{DialogAction::Decline};
        if !r.credentials.as_mut().is_some_and(Record::native_attempt)||!self.timely(){return Err(Refusal::NativePrecondition);}
        drop(r);
        let returned=observe_dialog_action(id,action).map_err(|error|match error.site{
            DialogActionSite::Binding=>Refusal::NativeActionBinding,DialogActionSite::FolderInput=>Refusal::NativeFolderInput,
            DialogActionSite::FolderSet=>Refusal::NativeFolderSet,DialogActionSite::FolderRead=>Refusal::NativeFolderRead,
            DialogActionSite::FolderCompare=>Refusal::NativeFolderCompare,DialogActionSite::FolderDifferent=>Refusal::NativeFolderDifferent,
            DialogActionSite::FolderInvalidated=>Refusal::NativeFolderInvalidated,DialogActionSite::State=>Refusal::NativeActionState,
            DialogActionSite::FileNameInput=>Refusal::NativeFileNameInput,DialogActionSite::FileNameSet=>Refusal::NativeFileNameSet,
            DialogActionSite::FileNameRead=>Refusal::NativeFileNameRead,DialogActionSite::FileNameDifferent=>Refusal::NativeFileNameDifferent,
        })?;
        if returned{Ok(Some(true))}else{Err(Refusal::NativeActionState)}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status(revision:u32)->Value { json!({"schemaVersion":2,"statusRevision":revision,"mode":"session","persistence":null,
        "capability":{"available":true,"reason":"none"},"context":null,"operation":null,"records":[],"assignments":[]}) }
    #[test]
    fn command_input_and_return_order_refuse_duplicates_and_stale_replacement() {
        let mut r=Record::new();r.step=SessionStep::Choose(0);
        assert!(!r.input(Command::Choose));assert!(!r.result_value(3,&status(2)));
        assert!(r.request(Command::Choose));assert!(!r.request(Command::Choose));
        assert!(!r.result_value(3,&status(2)));assert!(r.input(Command::Choose));assert!(!r.input(Command::Choose));
        assert!(r.result_value(3,&status(2)));assert!(!r.result_value(3,&status(2)));
        r.step=SessionStep::Chosen(0);assert!(!r.request(Command::Choose));
        r.step=SessionStep::Choose(1);assert!(r.request(Command::Choose));assert!(r.input(Command::Choose));
        assert!(r.status(&status(8))); // Read-only document overtook the first response snapshot.
        assert!(r.result_value(3,&status(7)));assert_eq!(r.status["statusRevision"],8);
        assert_eq!((r.requests[3],r.inputs[3],r.returns[3]),(2,2,2));
        assert!(!r.result_value(10,&status(9)));
        for mut invalid in [status(9),status(9),status(9),status(9)] .into_iter().enumerate() {
            match invalid.0 { 0=>invalid.1["schemaVersion"]=json!(1),1=>invalid.1["statusRevision"]=Value::Null,
                2=>invalid.1["records"]=json!([{}, {}, {}, {}]),_=>invalid.1["operation"]=json!({"settlement":"unknown"}) }
            assert!(!r.status(&invalid.1));assert_eq!(r.status["statusRevision"],8);
        }
        let mut r=Record::new();r.step=SessionStep::Open;assert!(!r.request(Command::Context));
        assert!(r.request(Command::Open));assert!(r.result_value(1,&status(1)));
        assert!(r.request(Command::Context));assert!(r.input(Command::Context));assert!(r.result_value(2,&status(2)));
        r.step=SessionStep::Ready;assert!(!r.request(Command::Context));
        r.step=SessionStep::Ios;assert!(r.request(Command::Context));assert!(r.input(Command::Context));assert!(r.result_value(2,&status(3)));
        r.step=SessionStep::IosReady;assert!(!r.request(Command::Context));
    }
    fn preview_snapshot()->WindowsSessionSnapshot {
        let mut value=status(7);
        value["operation"]=json!({"operationId":3,"operation":"prepare","phase":"preview","settlement":"known",
            "preview":{"action":"save","token":"synthetic-review","expiresInMs":1000}});
        // Deliberately no owner/finality. Arbitrary usize DATA tests pointer
        // tuple equality only; it is never dereferenced or admitted as an Arc.
        WindowsSessionSnapshot {status:value,owner:None,next_operation:3,payloads:vec![("synthetic".into(),1,1)],
            owner_settled:false,source_started:false,source_settled:false,empty:false}
    }
    #[test]
    fn dom_wait_cache_requires_same_revision_payload_and_nonrenewing_review() {
        let step=SessionStep::Prepared(0);let mut snapshot=preview_snapshot();
        let mut validated=ValidatedStep::capture(step,&snapshot).unwrap();
        assert!(validated.matches(step,&snapshot));
        snapshot.status["operation"]["preview"]["expiresInMs"]=json!(900);assert!(validated.matches(step,&snapshot));
        snapshot.status["operation"]["preview"]["expiresInMs"]=json!(901);assert!(!validated.matches(step,&snapshot));
        for change in [
            (|s:&mut WindowsSessionSnapshot|s.status["statusRevision"]=json!(8)) as fn(&mut WindowsSessionSnapshot),
            |s|s.status["operation"]["preview"]["token"]=json!("different-review"),
            |s|s.status["operation"]["preview"]["expiresInMs"]=json!(0),
            |s|s.payloads[0].2=2,|s|s.payloads[0].1=2,|s|s.next_operation=4,|s|s.source_started=true,|s|s.empty=true,
        ] {
            let mut current=preview_snapshot();let mut prior=ValidatedStep::capture(step,&current).unwrap();
            change(&mut current);assert!(!prior.matches(step,&current));
        }
        assert!(!validated.matches(SessionStep::Prepared(1),&preview_snapshot()));
        snapshot.status["operation"]["preview"]["expiresInMs"]=json!(0);assert!(ValidatedStep::capture(step,&snapshot).is_err());
    }
}
