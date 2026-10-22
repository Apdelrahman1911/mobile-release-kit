//! Actual private State/Entry methods with explicitly inert DATA. No native
//! Session, ticket, GO receipt, transport, credential read or filesystem is used.
use super::*;
use action_delegation::operation::tests as f;
use wire::{dispatch::Hex, operation::Snapshot};

fn prepared() -> p::Prepared {
    let target=p::Target{project_binding:"a".repeat(64),repository:"owner/app".into(),account_id:"11".into(),account_login:"owner".into(),owner_kind:p::OwnerKind::User,visibility:p::Visibility::Private,marker:"b".repeat(32)};
    let v=p::Prepared{confirmation:target.confirmation(),target,owner_id:"11".into(),membership:"self".into(),repository_observation:"not-found-or-inaccessible".into(),creation_permission:"not-proven".into(),auto_init:false};
    assert!(v.valid());v
}
#[test]
fn original_prepared_permission_withdrawal_requires_three_facts_and_preserves_later_consent() {
    for failed_history in [false,true] {
        let at=Instant::now();let mut s=f::state(at);let doc=Arc::new(());let root=f::root();let editor=f::editor(&doc);let edit=editor.saved_registration_guard(&doc).unwrap();
        let revision=s.repository_create_status(true,at,Reason::None).revision;
        let input=Input::RepositoryPrepare(Arc::new(p::PrepareArgs{session_id:"github-session-1".into(),expected_revision:revision,expected_connection_revision:s.status.revision,owner_kind:p::OwnerKind::User,visibility:p::Visibility::Private}));
        let review=s.repository_create_operation_review(input.clone(),2,&root,&"a".repeat(64),&edit,at,None).unwrap();
        let scope=f::scope(&doc,review.data.clone(),review.identity.clone(),at);s.repository_create_operation_allow(review,&scope).unwrap();
        let (_book,call,entry)=f::claim(scope.clone(),4);let command=input.repository_create_command().unwrap();
        s.repository_create_operation_entry(&command,Some(&entry),2,&root,&"a".repeat(64),&edit,at).unwrap();
        entry.entering().unwrap();entry.arm("repository-create-1").unwrap();entry.go("repository-create-1").unwrap();
        let value=prepared();let identity=Arc::new(());let id="c".repeat(32);
        s.repository_create.consent=Some(Consent{identity:identity.clone(),producer:Some(Producer::new(&entry,"repository-create-1")),agent:None,id:id.clone(),prepared:value.clone(),end:at+Duration::from_secs(120),session_id:"github-session-1".into(),project_id:"project-1".into(),generation:2,root:root.clone(),stamp:edit.stamp().unwrap()});
        s.repository_create.view.consent=Some(p::ConsentView{id:id.clone(),expires_at:"2026-09-17T12:02:00Z".into(),prepared:value.clone()});
        s.repository_create.view.operation=Some(p::Operation{id:"repository-create-1".into(),project_id:"project-1".into(),kind:p::Kind::Prepare,target:value.target.clone(),phase:p::Phase::Settled,reason:p::Reason::None,effect:p::Effect::None});
        // Native acceptance supplies only its fact. A public view is not used
        // to bypass either the real Claim or original History completion.
        s.repository_create_operation_returned(&Some(entry.clone()),"repository-create-1");
        assert_eq!(entry.status().unwrap().state,wire::State::Finishing);
        s.repository_create_operation_revoke(&scope);
        assert!(s.repository_create.agent_permission.is_some());assert!(Arc::ptr_eq(&s.repository_create.consent.as_ref().unwrap().identity,&identity));
        assert!(s.repository_create_operation_origin(&command,None).is_err());
        call.returned(Ok(()));let history=entry.claim_history().unwrap().unwrap();
        if failed_history {drop(history);}else{history.returned(Ok(())).unwrap();}
        s.repository_create_operation_revoke(&scope);
        let consent=s.repository_create.consent.as_ref().unwrap();assert!(Arc::ptr_eq(&consent.identity,&identity));assert_eq!(consent.prepared,value);
        let selection=action_delegation::Selection::RepositoryCreate(wire::PreparedSelection{session_id:"github-session-1".into(),consent_id:id,expected_revision:s.repository_create.view.revision});
        if failed_history {
            assert!(s.repository_create.agent_permission.is_some());assert!(!producer_ready(&consent.producer));assert!(entry.pending());
            assert!(s.repository_create_agent_review(&selection,2,&root,&edit,at).is_err());
            assert_eq!(entry.status().unwrap().state,wire::State::Unknown);
        } else {
            assert!(s.repository_create.agent_permission.is_none());assert!(producer_ready(&consent.producer));assert!(!entry.pending());
            let next=s.repository_create_agent_review(&selection,2,&root,&edit,at).unwrap();let next_scope=f::scope(&doc,next.data.clone(),next.identity.clone(),at);
            s.repository_create_agent_allow(&next,&next_scope).unwrap();
            s.repository_create_operation_revoke(&scope); // old late withdrawal cannot touch the new Create permission
            assert!(s.repository_create.consent.as_ref().unwrap().agent.as_ref().unwrap().upgrade().is_some_and(|a|Arc::ptr_eq(&a,&next_scope)));
            assert!(next_scope.current(false).is_ok());
        }
    }
}
#[test]
fn original_full_pending_witness_requires_same_roster_source_and_returned_producer() {
    let at=Instant::now();let mut s=f::state(at);let doc=Arc::new(());let root=f::root();let editor=f::editor(&doc);let edit=editor.saved_registration_guard(&doc).unwrap();
    let revision=s.repository_create_status(true,at,Reason::None).revision;
    let input=Input::RepositoryPending(Arc::new(p::PendingArgs{session_id:"github-session-1".into(),expected_revision:revision,expected_connection_revision:s.status.revision}));
    let review=s.repository_create_operation_review(input,2,&root,&"a".repeat(64),&edit,at,None).unwrap();let scope=f::scope(&doc,review.data.clone(),review.identity.clone(),at);s.repository_create_operation_allow(review,&scope).unwrap();
    let (_book,call,entry)=f::claim(scope.clone(),4);entry.entering().unwrap();entry.arm("repository-create-1").unwrap();entry.go("repository-create-1").unwrap();
    let rows:Vec<_>=(0..32).map(|n|{let mut v=prepared();v.target.marker=format!("{n:032x}");v.confirmation=v.target.confirmation();p::Pending{prepared:v,claimed:false,acknowledged:None}}).collect();
    s.repository_create.view.pending=rows.clone();s.repository_create.view.operation=Some(p::Operation{id:"repository-create-1".into(),project_id:"project-1".into(),kind:p::Kind::Pending,target:prepared().target,phase:p::Phase::Settled,reason:p::Reason::None,effect:p::Effect::None});
    let identity=Arc::new(());s.repository_create.agent_records=Some(Records{identity:identity.clone(),original:"repository-create-1".into(),session:"github-session-1".into(),generation:2,root:root.clone(),stamp:edit.stamp().unwrap(),end:at+Duration::from_secs(60),digest:hash(&rows).unwrap(),producer:Some(Producer::new(&entry,"repository-create-1"))});
    s.repository_create_operation_returned(&Some(entry.clone()),"repository-create-1");
    s.repository_create_operation_revoke(&scope);assert!(s.repository_create.agent_records.is_some()&&s.repository_create.agent_permission.is_some());
    call.returned(Ok(()));entry.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();s.repository_create_operation_revoke(&scope);
    let captured=s.repository_create.agent_records.as_ref().unwrap();assert!(Arc::ptr_eq(&captured.identity,&identity));assert!(captured.current(&rows,Some("repository-create-1"),"github-session-1",2,&root,&edit,at));
    let input=Input::RepositoryReconcile(Arc::new(p::ReconcileArgs{session_id:"github-session-1".into(),expected_revision:s.repository_create.view.revision,marker:rows[31].prepared.target.marker.clone()}));
    let r=s.repository_create_operation_review(input.clone(),2,&root,&"a".repeat(64),&edit,at,None).unwrap();assert!(Arc::ptr_eq(&r.identity,&identity));
    s.repository_create.view.pending[31].claimed=true;assert!(s.repository_create_operation_review(input.clone(),2,&root,&"a".repeat(64),&edit,at,None).is_err());s.repository_create.view.pending=rows;
    assert!(s.repository_create_operation_review(input.clone(),3,&root,&"a".repeat(64),&edit,at,None).is_err());
    assert!(s.repository_create_operation_review(input,2,&root,&"a".repeat(64),&edit,at+Duration::from_secs(60),None).is_err());
    let data=entry.status().unwrap();assert!(matches!(data.result,Some(wire::dispatch::Snapshot::Operation(Snapshot::Pending{rows})) if rows.len()==32&&rows[31].marker==Hex::parse(&format!("{:032x}",31)).unwrap()));
}
