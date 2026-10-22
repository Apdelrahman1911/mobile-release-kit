//! Existing inert Connection/Edit/Book methods only. No credential acquisition,
//! Supervisor ticket, native/source admission, provider call or receipt is made.
use super::*;
use crate::{edit_owner::EditOwner, runtime::RuntimeConfig, service_protocol::Id};
use serde_json::{json, Value};
use std::path::PathBuf;

pub(crate) fn root() -> RegisteredRoot {
    RegisteredRoot { path: "/never-opened-operation-delegation".into(),
        identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) }
}
pub(crate) fn editor(doc: &Arc<()>) -> EditOwner {
    let e=EditOwner::new(RuntimeConfig::packaged(PathBuf::from("/never-opened-operation-edit")));
    e.bind_saved_registration(doc,Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()));
    e.initial_document("main").unwrap();e
}
pub(crate) fn state(at: Instant) -> ConnectionState {
    use crate::github_connection_protocol::{Visibility,Permissions,Permission as P,Coverage,Workflow,Presence,WorkflowState};
    use crate::github_workflow_edit_protocol::WorkflowId;
    fn observed<T>(value:T)->Fact<T>{Fact {state:FactState::Observed,value:Some(value),observed_at:Some("2026-09-17T12:00:01Z".into()),reason:Reason::None}}
    let mut s=crate::github_connection_session::tests::fixture(at);
    s.accept_final(Ok(GitHubReadOutcome{facts:GitHubReadFacts{schema_version:1,
        account:observed(Account{id:"11".into(),login:"owner".into()}),
        repository:observed(Repository{id:"22".into(),full_name:"owner/app".into(),default_branch:"main".into(),visibility:Visibility::Private,archived:false,
            permissions:Permissions{pull:P::ReportedAllowed,push:P::Unknown,admin:P::Unknown}}),
        automation:observed(Automation{coverage:Coverage::Complete,workflows:[WorkflowId::Preflight,WorkflowId::Candidate,WorkflowId::ExternalTesting,WorkflowId::ProductionSubmit]
            .into_iter().map(|id|Workflow{id,remote_id:None,presence:Presence::NotListed,state:WorkflowState::Unknown}).collect()})},
        control:GitHubReadControl{reason:Reason::None,credential_expires_at:None,cooldown_seconds:None,cooldown_blocked:false}}),at,false,at);
    s.capability(at,Reason::None);assert!(!s.native_work_pending());s
}
fn choices() -> Vec<Value> {
    ["repository","pr","failed-jobs"].into_iter().flat_map(|family| ["prepare","pending","reconcile"].map(|phase| {
        let mut v=json!({"kind":format!("{family}-{phase}"),"sessionId":"github-session-1","expectedRevision":1});
        if phase=="reconcile" {v["marker"]=json!("a".repeat(32));}
        else {v["expectedConnectionRevision"]=json!(3);}
        if phase=="prepare" {match family {
            "repository"=>{v["ownerKind"]=json!("user");v["visibility"]=json!("private");},
            "pr"=>v["draft"]=json!({"base":"main","head":"feature/example","title":"An actual draft","body":"Preserve this private text."}),
            _=>{v["activityRevision"]=json!(4);v["runId"]=json!("31");v["attempt"]=json!(2);},
        }}v
    })).collect()
}
fn input(v:Value)->Input {serde_json::from_value::<super::super::dispatch::Selection>(v).unwrap().operation_input().unwrap()}
pub(crate) fn id(n:u64)->Id {Id::parse(&format!("{n:032x}")).unwrap()}
pub(crate) fn scope(doc:&Arc<()>,data:p::Review,identity:Arc<()>,at:Instant)->Arc<r::NativeScope> {
    r::NativeScope::new(id(1),"project-1".into(),root().path,1,2,3,data,identity,at+Duration::from_secs(60),
        Arc::new(crate::service_version_reserve_requests::ReadPermission::new(at+Duration::from_secs(80))),Arc::downgrade(doc),tokio::sync::watch::channel(1).0)
}
pub(crate) fn claim(scope:Arc<r::NativeScope>,n:u64)->(r::Inbox,r::Claim,Arc<r::Entry>) {
    let book=r::Inbox::new(id(2));book.allow(scope,id(3)).unwrap();book.submit(p::Submit{origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(n)},grant_id:id(3)}).unwrap();
    let call=book.claim().unwrap().unwrap();let entry=call.entry().clone();(book,call,entry)
}

#[test]
fn nine_operation_inputs_keep_native_commands_hashes_and_closed_old_forms() {
    for v in choices() {
        let s:super::super::dispatch::Selection=serde_json::from_value(v.clone()).unwrap();
        assert!(s.valid()&&s.retained_fits());assert!(s.legacy().is_none()&&s.input().is_none());
        let i=s.operation_input().unwrap();assert_eq!(i.kind(),s.kind());assert!(i.retained_fits());
        let raw=serde_json::to_vec(&i).unwrap();assert_eq!(hash(&i).unwrap(),format!("{:x}",Sha256::digest(&raw)));
        assert_eq!([i.repository_create_command().is_ok(),i.pull_request_command().is_ok(),i.actions_retry_command().is_ok()].into_iter().filter(|b|*b).count(),1);
        let mut changed=v.clone();changed["expectedRevision"]=json!(2);assert_ne!(hash(&i).unwrap(),hash(&input(changed)).unwrap());
        for key in ["token","url","path","accountId","confirm","force","prepared"] {
            let mut bad=v.clone();bad[key]=json!("not-authority");assert!(serde_json::from_value::<super::super::dispatch::Selection>(bad).is_err(),"{key}");
        }
        assert!(serde_json::from_slice::<p::Selection>(&raw).is_err()); // CLI still only IDs
        assert!(!i.kind().mutation());assert_ne!(i.kind().consent(),p::Kind::RepositoryCreate.consent());
        let text=String::from_utf8(raw).unwrap();let duplicate=text.replacen("\"sessionId\":","\"sessionId\":\"other\",\"sessionId\":",1);
        assert!(serde_json::from_str::<super::super::dispatch::Selection>(&duplicate).is_err());
    }
    for kind in [p::Kind::RepositoryCreate,p::Kind::DraftPrCreate,p::Kind::PrCreate,p::Kind::FailedJobsRetry] {
        let v=json!({"kind":kind,"sessionId":"github-session-1","expectedRevision":1,"consentId":"a".repeat(32)});
        let s:super::super::dispatch::Selection=serde_json::from_value(v).unwrap();assert!(s.valid());assert_eq!(s.limit(),1024);assert!(s.operation_input().is_none());
    }
}
#[test]
fn maximum_private_pr_shares_one_real_allocation_and_keeps_native_modes_and_capacity_checks() {
    for ready in [false,true] {
        let mut v=choices()[3].clone();
        v["draft"]=json!({"base":"b".repeat(200),"head":"h".repeat(200),"title":"é".repeat(128),"body":"\"\\\n".repeat(1365)+"x"});
        if ready {v["draft"]["creationMode"]=json!("ready-for-review");}
        let selected:super::super::dispatch::Selection=serde_json::from_value(v.clone()).unwrap();let a=selected.operation_input().unwrap();let b=selected.operation_input().unwrap();
        assert!(a.retained_fits());assert!(a.same_original(&b));assert!(!a.same_original(&input(v.clone())));assert_eq!(selected.limit(),MAIN_RAW_LIMIT);
        let command=a.pull_request_command().unwrap();let pr::Command::Prepare(args)=command else {panic!("not original PR Prepare")};
        let raw=serde_json::to_vec(&args).unwrap();assert!(raw.len()>4096&&raw.len()<=16*1024);
        assert!(matches!(pr::decode_command("github_pull_request_prepare",&pr::raw_input("github_pull_request_prepare",&raw).unwrap()).unwrap(),pr::Command::Prepare(_)));
        let mut bad=v.clone();bad["draft"]["creationMode"]=Value::Null;assert!(serde_json::from_value::<super::super::dispatch::Selection>(bad).is_err());
        let mut excessive=input(v);let Input::PrPrepare(a)=&mut excessive else{unreachable!()};
        Arc::get_mut(a).unwrap().draft.body.reserve_exact(INPUT_BACKING+1);
        assert!(excessive.valid());assert!(!excessive.retained_fits());
    }
}
#[test]
fn original_capture_preserves_account_only_repository_and_exact_retry_witness_requirement() {
    let at=Instant::now();let mut s=state(at);let root=root();let binding="a".repeat(64);
    let mut v=choices()[0].clone();v["expectedConnectionRevision"]=json!(s.status.revision);
    let repo=input(v);let first=s.operation_capture(repo.clone(),2,&root,&binding,at).unwrap();
    assert!(first.repository.is_none()&&first.retained_fits());
    s.status.repository.state=FactState::Unavailable;s.status.repository.value=None;
    assert!(s.operation_capture(repo.clone(),2,&root,&binding,at).is_ok()); // no fake absence/observed repo prerequisite
    let mut v=choices()[3].clone();v["expectedConnectionRevision"]=json!(s.status.revision);
    assert!(s.operation_capture(input(v),2,&root,&binding,at).is_err());
    assert!(s.operation_capture(repo.clone(),3,&root,&binding,at).is_err());
    assert!(s.operation_capture(repo.clone(),2,&root,&binding,first.credential_end).is_err());
    s.status.account.value.as_mut().unwrap().id="12".into();assert!(s.operation_capture(repo,2,&root,&binding,at).is_err());
    let s=state(at);let mut v=choices()[6].clone();v["expectedConnectionRevision"]=json!(s.status.revision);
    assert!(s.operation_capture(input(v),2,&root,&binding,at).is_err()); // IDs alone cannot substitute for actual Activity
}
#[test]
fn all_three_origin_checks_precede_retirement_and_claim_once_on_same_private_input() {
    // Entry's one temporary Review is gone before original native admission.
    // The private Input Arc is already in the inline retained Permission; only
    // the temporary root/context, Box payload and move frontier are additional.
    let entry_bytes=[std::mem::size_of::<super::super::Review>(),2*std::mem::size_of::<Capture>(),
        ROOT_BACKING,CONTEXT_BACKING,2048].into_iter().try_fold(0usize,|n,v|n.checked_add(v)).unwrap();
    assert!(entry_bytes<=16*1024,"original per-owner transition/return reserve: {entry_bytes}");
    for family in 0..3 {
        let at=Instant::now();let mut s=state(at);let doc=Arc::new(());let editor=editor(&doc);let edit=editor.saved_registration_guard(&doc).unwrap();let root=root();
        let revision=match family {0=>s.repository_create_status(true,at,Reason::None).revision,1=>s.pull_request_status(true,at,Reason::None).revision,_=>s.actions_retry_status(true,at,Reason::None).revision};
        let mut v=choices()[family*3+1].clone();v["expectedRevision"]=json!(revision);v["expectedConnectionRevision"]=json!(s.status.revision);let i=input(v);
        let review=match family {0=>s.repository_create_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None),1=>s.pull_request_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None),_=>s.actions_retry_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None)}.unwrap();
        let current=match family {0=>s.repository_create_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None),1=>s.pull_request_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None),_=>s.actions_retry_operation_review(i.clone(),2,&root,&"a".repeat(64),&edit,at,None)}.unwrap();
        let first:&Box<Capture>=review.operation.as_ref().unwrap();let second:&Box<Capture>=current.operation.as_ref().unwrap();
        assert!(!std::ptr::eq(first.as_ref(),second.as_ref()));assert!(first.same(second));
        assert!(first.input.same_original(&i)&&second.input.same_original(&i));
        let capture_heap=first.heap().unwrap();let before=s.retained_heap_bytes_if_quiescent().unwrap();
        drop(current); // Same final Doc cut; no second Box survives installation.
        let sc=scope(&doc,review.data.clone(),review.identity.clone(),at);let foreign=scope(&doc,review.data.clone(),review.identity.clone(),at);
        match family {0=>s.repository_create_operation_allow(review,&sc),1=>s.pull_request_operation_allow(review,&sc),_=>s.actions_retry_operation_allow(review,&sc)}.unwrap();
        assert_eq!(s.retained_heap_bytes_if_quiescent(),before.checked_add(capture_heap));
        let (_book,call,entry)=claim(sc,4);let (_other,other,wrong)=claim(foreign,5);
        let installed=match family {0=>s.repository_create_operation_input(&entry),1=>s.pull_request_operation_input(&entry),_=>s.actions_retry_operation_input(&entry)}.unwrap();
        assert!(installed.same_original(&i));
        macro_rules! check {($command:expr,$origin:ident,$enter:ident)=>{{let command=$command.unwrap();
            assert!(s.$origin(&command,None).is_err());assert!(s.$origin(&command,Some(&wrong)).is_err());assert!(s.$origin(&command,Some(&entry)).is_ok());
            s.$enter(&command,Some(&entry),2,&root,&"a".repeat(64),&edit,at).unwrap();
            assert!(s.$origin(&command,Some(&entry)).is_err());assert!(s.$enter(&command,Some(&entry),2,&root,&"a".repeat(64),&edit,at).is_err());}}}
        match family {0=>check!(i.repository_create_command(),repository_create_operation_origin,repository_create_operation_entry),1=>check!(i.pull_request_command(),pull_request_operation_origin,pull_request_operation_entry),_=>check!(i.actions_retry_command(),actions_retry_operation_origin,actions_retry_operation_entry)};
        assert!(!s.native_work_pending());assert!(s.operation_permission_retained());
        call.returned(Err(p::Reason::ContextChanged));other.returned(Err(p::Reason::ContextChanged));
        assert!(entry.status().unwrap().never_admitted);assert!(entry.pending()); // no native finality supplied
    }
}
