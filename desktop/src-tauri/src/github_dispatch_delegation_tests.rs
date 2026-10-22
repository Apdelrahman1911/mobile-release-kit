//! Original comparison/Book/Registry DATA only. No Supervisor, source, Host,
//! filesystem, provider call or synthetic native qualification is entered.
use super::*;
use crate::{edit_owner::EditOwner, runtime::RuntimeConfig, service_protocol::Id};
use serde_json::{json,Value};
use std::{path::PathBuf,time::Duration};

fn choice()->Value {json!({"stage":"candidate","candidateRunId":null,"externalRunId":null,
    "recoveryRunId":null,"originalSourceSha":null,"originalVersion":null})}
fn selections()->Vec<Value> {
    vec![
        json!({"kind":"preflight-prepare","sessionId":"github-session-1","expectedRevision":1,"expectedConnectionRevision":3,"branch":"main","platform":"both"}),
        json!({"kind":"preflight-dispatch","sessionId":"github-session-1","expectedRevision":1,"consentId":"a".repeat(32),"confirm":true}),
        json!({"kind":"preflight-pending","sessionId":"github-session-1","expectedRevision":1}),
        json!({"kind":"preflight-observe","sessionId":"github-session-1","expectedRevision":1,"marker":"a".repeat(32),"observe":"track","runId":"44"}),
        json!({"kind":"release-prepare","sessionId":"github-session-1","expectedRevision":1,"expectedConnectionRevision":3,"branch":"main","platform":"ios","selection":choice()}),
        json!({"kind":"release-dispatch","sessionId":"github-session-1","expectedRevision":1,"consentId":"a".repeat(32),"confirm":true,"confirmation":"candidate:ios:1.0.0:1"}),
        json!({"kind":"release-pending","sessionId":"github-session-1","expectedRevision":1}),
        json!({"kind":"release-observe","sessionId":"github-session-1","expectedRevision":1,"marker":"a".repeat(32),"observe":"reconcile","runId":null}),
        json!({"kind":"counter-prepare","sessionId":"github-session-1","expectedRevision":1,"expectedConnectionRevision":3,"base":"main","purpose":"version-counter"}),
        json!({"kind":"counter-create","sessionId":"github-session-1","expectedRevision":1,"consentId":"a".repeat(32),"confirm":true}),
        json!({"kind":"publication-pending","sessionId":"github-session-1","expectedRevision":1,"expectedConnectionRevision":3}),
        json!({"kind":"counter-reconcile","sessionId":"github-session-1","expectedRevision":1,"marker":"a".repeat(32)}),
    ]
}
fn input(v:Value)->Input {serde_json::from_value::<Selection>(v).unwrap().input().unwrap()}
fn root()->RegisteredRoot {RegisteredRoot{path:"/never-opened-dispatch-capture".into(),
    identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())}}
fn observed<T>(value:T)->Fact<T>{Fact{state:FactState::Observed,value:Some(value),
    observed_at:Some("2026-09-17T12:00:01Z".into()),reason:Reason::None}}
fn state(at:Instant)->ConnectionState {
    use crate::github_connection_protocol::{Visibility,Permissions,Permission as P,Coverage,Workflow,Presence,WorkflowState};
    use crate::github_workflow_edit_protocol::WorkflowId;
    let mut s=crate::github_connection_session::tests::fixture(at);
    s.accept_final(Ok(GitHubReadOutcome{facts:GitHubReadFacts{schema_version:1,
        account:observed(Account{id:"11".into(),login:"owner".into()}),repository:observed(Repository{
            id:"22".into(),full_name:"owner/app".into(),default_branch:"main".into(),visibility:Visibility::Private,
            archived:false,permissions:Permissions{pull:P::ReportedAllowed,push:P::Unknown,admin:P::Unknown}}),
        automation:observed(Automation{coverage:Coverage::Complete,workflows:[WorkflowId::Preflight,WorkflowId::Candidate,
            WorkflowId::ExternalTesting,WorkflowId::ProductionSubmit].into_iter().map(|id|Workflow{id,remote_id:None,
                presence:Presence::NotListed,state:WorkflowState::Unknown}).collect()})},
        control:GitHubReadControl{reason:Reason::None,credential_expires_at:None,cooldown_seconds:None,cooldown_blocked:false}}),at,false,at);
    s.capability(at,Reason::None);assert!(!s.native_work_pending());s
}

#[test]
fn twelve_native_inputs_map_only_to_existing_typed_commands_and_hash_exact_fields() {
    for v in selections() {
        let s:Selection=serde_json::from_value(v.clone()).unwrap();assert!(s.valid());assert!(s.retained_fits());assert!(s.legacy().is_none());
        let i=s.input().unwrap();assert_eq!(i.kind(),s.kind());assert!(i.valid());
        assert_eq!(i.hash().unwrap(),format!("{:x}",Sha256::digest(serde_json::to_vec(&i).unwrap())));
        let valid=[i.preflight_command().is_ok(),i.release_command().is_ok(),i.counter_command().is_ok()];
        assert_eq!(valid.into_iter().filter(|v|*v).count(),1);
        let mut changed=v.clone();changed["expectedRevision"]=json!(2);assert_ne!(i.hash().unwrap(),input(changed).hash().unwrap());
        for key in ["path","url","token","workflow","ledgerId"] {let mut bad=v.clone();bad[key]=json!("inert");assert!(serde_json::from_value::<Selection>(bad).is_err());}
    }
    for mut v in selections().into_iter().filter(|v|v["kind"]=="preflight-observe"||v["kind"]=="release-observe") {
        v["runId"]=if v["observe"]=="track"{Value::Null}else{json!("44")};
        assert!(!serde_json::from_value::<Selection>(v).unwrap().valid());
    }
    let mut counter=selections()[8].clone();counter["purpose"]=json!("setup-pr");
    assert!(serde_json::from_value::<Selection>(counter).is_err());
}

#[test]
fn release_all_six_stage_platform_inputs_preserve_real_lineage_and_recovery_rules() {
    for platform in ["android","ios"] {for stage in ["candidate","external-testing","production-submit"] {
        let mut v=selections()[4].clone();v["platform"]=json!(platform);v["selection"]["stage"]=json!(stage);
        if stage!="candidate" {v["selection"]["candidateRunId"]=json!("40");v["selection"]["originalSourceSha"]=json!("a".repeat(40));
            v["selection"]["originalVersion"]=json!({"name":"1.0.0","build":7});}
        if stage=="production-submit" {v["selection"]["externalRunId"]=json!("41");}
        assert!(input(v.clone()).valid(),"{platform}/{stage}");
        let mut both=v.clone();both["platform"]=json!("both");assert!(serde_json::from_value::<Selection>(both).is_err());
        if stage!="candidate" {let mut bad=v.clone();bad["selection"]["originalSourceSha"]=Value::Null;assert!(!input(bad).valid());}
        v["selection"]["recoveryRunId"]=json!("42");v["selection"]["originalSourceSha"]=json!("a".repeat(40));
        v["selection"]["originalVersion"]=json!({"name":"1.0.0","build":7});
        assert!(input(v.clone()).valid());
        // Optional recovery confirmation is absent or an actual iOS native form;
        // null cannot silently become absence and Android cannot borrow it.
        v["selection"]["recoveryConfirmation"]=Value::Null;assert!(serde_json::from_value::<Selection>(v).is_err());
    }}
}

#[test]
fn actual_capture_requires_selected_account_repo_generation_and_original_clock() {
    let at=Instant::now();let mut s=state(at);let root=root();let binding="a".repeat(64);
    let mut v=selections()[0].clone();v["expectedConnectionRevision"]=json!(s.status.revision);
    let i=input(v);let c=s.dispatch_capture(i.clone(),2,&root,&binding,at).unwrap();assert!(c.retained_fits());
    assert!(s.dispatch_capture(i.clone(),3,&root,&binding,at).is_err());
    let mut stale=i.clone();if let Input::PreflightPrepare(v)=&mut stale{v.expected_connection_revision+=1;}
    assert!(s.dispatch_capture(stale,2,&root,&binding,at).is_err());
    assert!(s.dispatch_capture(i.clone(),2,&root,&binding,c.credential_end).is_err());
    s.status.account.value.as_mut().unwrap().id="12".into();assert!(s.dispatch_capture(i.clone(),2,&root,&binding,at).is_err());
    s.status.account.value.as_mut().unwrap().id="11".into();s.status.repository.value.as_mut().unwrap().id="23".into();
    assert!(s.dispatch_capture(i.clone(),2,&root,&binding,at).is_err());
    s.status.repository.value.as_mut().unwrap().id="22".into();s.cooldown_blocked=true;
    assert!(s.dispatch_capture(i.clone(),2,&root,&binding,at).is_err());s.cooldown_blocked=false;
    let mut changed=root.clone();changed.path.push("changed");
    assert!(s.dispatch_capture(i,2,&changed,&binding,at).unwrap()!=c); // full exact root equality retained
    let mut excessive=c;excessive.root.path.reserve(ROOT_BACKING+1);assert!(!excessive.retained_fits());
}

#[test]
fn original_record_witness_rechecks_full_rows_and_same_private_edit_owner() {
    let owner=EditOwner::new(RuntimeConfig::packaged(PathBuf::from("/never-opened-dispatch-edit")));
    let doc=Arc::new(());owner.bind_saved_registration(&doc,Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()));
    owner.initial_document("main").unwrap();let guard=owner.saved_registration_guard(&doc).unwrap();
    let rows=json!([{"marker":"a".repeat(32),"fullPrivatePrepared":{"source":"b".repeat(40),"run":"44"}}]);
    let at=Instant::now();let root=root();let witness=Records{identity:Arc::new(()),original:"github-preflight-1".into(),
        session:"github-session-1".into(),generation:2,root:root.clone(),stamp:guard.stamp().unwrap(),
        end:at+Duration::from_secs(30),digest:hash(&rows).unwrap(),producer:None};
    assert!(witness.current(&rows,Some("github-preflight-1"),"github-session-1",2,&root,&guard,at));
    let mut changed=rows.clone();changed[0]["fullPrivatePrepared"]["source"]=json!("c".repeat(40));
    assert!(!witness.current(&changed,Some("github-preflight-1"),"github-session-1",2,&root,&guard,at));
    for (op,session,generation,time) in [(Some("github-preflight-2"),"github-session-1",2,at),
        (None,"github-session-1",2,at),(Some("github-preflight-1"),"other",2,at),
        (Some("github-preflight-1"),"github-session-1",3,at),(Some("github-preflight-1"),"github-session-1",2,witness.end)] {
        assert!(!witness.current(&rows,op,session,generation,&root,&guard,time));
    }
}

#[test]
fn producer_weak_entry_queries_final_facts_not_the_retired_consumer_scope() {
    let doc=Arc::new(());let at=Instant::now();let id=|n:u64|Id::parse(&format!("{n:032x}")).unwrap();
    let scope=r::NativeScope::new(id(1),"project-1".into(),"/never-opened-producer".into(),1,2,3,
        p::Review::PreflightPending(p::dispatch::RequestReference{session_id:"github-session-1".into(),expected_revision:4,request_sha256:"b".repeat(64)}),
        Arc::new(()),at+Duration::from_secs(60),Arc::new(crate::service_version_reserve_requests::ReadPermission::new(at+Duration::from_secs(80))),
        Arc::downgrade(&doc),tokio::sync::watch::channel(1).0);
    let inbox=r::Inbox::new(id(2));inbox.allow(scope.clone(),id(3)).unwrap();inbox.submit(p::Submit{
        origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(4)},grant_id:id(3)}).unwrap();
    let call=inbox.claim().unwrap().unwrap();let e=call.entry().clone();let producer=Producer::new(&e,"github-preflight-1");
    e.entering().unwrap();e.arm("github-preflight-1").unwrap();e.go("github-preflight-1").unwrap();
    e.dispatch_returned("github-preflight-1",p::Reason::None,p::Effect::None,Some(p::dispatch::Snapshot::Pending{rows:vec![]}));
    assert!(!producer.positive());call.returned(Ok(()));assert!(!producer.positive());
    e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();assert!(producer.positive());
    assert!(scope.current(false).is_err());e.cancel(p::Reason::UserCancelled,at);assert!(producer.positive());
    drop(inbox);drop(e);assert!(!producer.positive()); // dead producer is never reconstructed from an ID
}
