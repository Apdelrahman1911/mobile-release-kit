//! Closed wire and existing Book DATA transitions; supplied facts are not
//! Supervisor/caller/provider evidence. Full retained results are never sliced.
use super::*;
use super::super as p;
use crate::{service_github_action_requests as r,service_protocol::Id};
use std::{sync::Arc,time::{Duration,Instant}};
fn id(n:u64)->Id {Id::parse(&format!("{n:032x}")).unwrap()}
fn records()->Vec<Record>{(0..ROWS).map(|n|Record{marker:Hex::parse(&format!("{n:032x}")).unwrap(),record_sha256:Hex::parse(&"a".repeat(64)).unwrap(),claimed:n%2==0,acknowledged:n%4==0,closed:false}).collect()}
fn review(kind:Kind)->p::Review {
    let v=serde_json::json!({"kind":kind,"sessionId":"github-session-1","expectedRevision":4,
        "requestSha256":"a".repeat(64)});
    if kind.operation_reconcile(){serde_json::from_value(serde_json::json!({"kind":kind,"sessionId":"github-session-1","expectedRevision":4,"marker":"b".repeat(32),"recordSha256":"a".repeat(64)})).unwrap()}
    else if kind==Kind::RepositoryCreate {p::Review::RepositoryCreate(p::PreparedReference{session_id:"github-session-1".into(),expected_revision:4,consent_id:"b".repeat(32),prepared_sha256:"a".repeat(64)})}
    else{serde_json::from_value(v).unwrap()}
}
fn scope(doc:&Arc<()>,kind:Kind)->Arc<r::NativeScope>{let at=Instant::now();r::NativeScope::new(id(1),"project-1".into(),"/never-opened-operation-book".into(),1,2,3,review(kind),Arc::new(()),
    at+Duration::from_secs(60),Arc::new(crate::service_version_reserve_requests::ReadPermission::new(at+Duration::from_secs(80))),Arc::downgrade(doc),tokio::sync::watch::channel(1).0)}
fn entry(doc:&Arc<()>,kind:Kind)->(r::Inbox,r::Claim,Arc<r::Entry>){let book=r::Inbox::new(id(2));book.allow(scope(doc,kind),id(3)).unwrap();book.submit(p::Submit{origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(4)},grant_id:id(3)}).unwrap();let c=book.claim().unwrap().unwrap();let e=c.entry().clone();(book,c,e)}
fn arm(e:&r::Entry,go:bool)->String{let op=format!("{}1",e.scope().review.kind().prefix());e.entering().unwrap();e.arm(&op).unwrap();if go{e.go(&op).unwrap();}op}
#[test]
fn full_operation_pending_wire_keeps_all_rows_actual_backing_and_id_strings() {
    let s=Snapshot::Pending{rows:records()};assert!(s.valid_for(Kind::PrPending));
    assert!(s.heap().unwrap()+size_of::<p::dispatch::Snapshot>()+2*size_of::<usize>()<=p::dispatch::SNAPSHOT_BACKING);
    let doc=Arc::new(());let (_book,c,e)=entry(&doc,Kind::PrPending);let op=arm(&e,true);
    e.operation_returned(&op,Reason::None,Effect::None,Some(s.clone()));c.returned(Ok(()));e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
    let status=e.status().unwrap();assert_eq!(status.state,State::Complete);status.validate().unwrap();
    let bytes=serde_json::to_vec(&status).unwrap();assert!(bytes.len()<=p::dispatch::RESPONSE_LIMIT);let round:p::Status=serde_json::from_slice(&bytes).unwrap();assert_eq!(round,status);
    assert_eq!(serde_json::to_value(Number(u64::MAX)).unwrap(),serde_json::json!(u64::MAX.to_string()));
    for bad in [serde_json::json!(0),serde_json::json!("0"),serde_json::json!("01"),serde_json::json!("18446744073709551616")]{assert!(serde_json::from_value::<Number>(bad).is_err());}
    let mut v=serde_json::to_value(s).unwrap();let first=v["rows"][0].clone();v["rows"].as_array_mut().unwrap().push(first);assert!(serde_json::from_value::<Snapshot>(v).is_err());
    let mut grown=records();grown.reserve_exact(ROWS);assert!(!Snapshot::Pending{rows:grown}.valid_for(Kind::PrPending));
    let mut duplicate=records();duplicate[1].marker=duplicate[0].marker;assert!(!Snapshot::Pending{rows:duplicate}.valid_for(Kind::PrPending));
    let mut malformed=records();malformed[1].acknowledged=true;assert!(!Snapshot::Pending{rows:malformed}.valid_for(Kind::RepositoryPending));
    let mut closed=records();closed[0].closed=true;assert!(!Snapshot::Pending{rows:closed.clone()}.valid_for(Kind::RepositoryPending));assert!(Snapshot::Pending{rows:closed}.valid_for(Kind::PrPending));
}
#[test]
fn operation_producer_needs_go_original_caller_and_latest_history_not_progress() {
    let doc=Arc::new(());let (_book,c,e)=entry(&doc,Kind::RepositoryPending);let op=arm(&e,true);
    let progress=e.claim_history().unwrap().unwrap();e.operation_returned(&op,Reason::None,Effect::None,Some(Snapshot::Pending{rows:records()}));
    assert!(!e.positively_returned(&op));c.returned(Ok(()));assert!(!e.positively_returned(&op));
    progress.returned(Ok(())).unwrap();assert!(!e.positively_returned(&op));e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();assert!(e.positively_returned(&op));
    for missing in ["go","result","caller","history"] {
        let (_book,c,e)=entry(&doc,Kind::RepositoryPending);let op=arm(&e,missing!="go");
        e.operation_returned(&op,Reason::None,Effect::None,if missing=="result"{None}else{Some(Snapshot::Pending{rows:records()})});
        if missing=="caller" {drop(c);}else{c.returned(Ok(()));}
        if missing=="history"{drop(e.claim_history().unwrap().unwrap());}
        assert_eq!(e.status().unwrap().state,State::Unknown, "{missing}");assert!(e.pending());assert!(!e.positively_returned(&op));
    }
}
#[test]
fn known_unattributed_reconcile_is_retained_data_but_earlier_read_stop_removes_attribution() {
    for stopped in [false,true] {
        let doc=Arc::new(());let (_book,c,e)=entry(&doc,Kind::PrReconcile);let op=arm(&e,true);
        let s=Snapshot::Reconciled{marker:Hex::parse(&"b".repeat(32)).unwrap(),effect:Effect::FoundUnattributed,observed:Some(Observation::Pr{id:Number(31),number:Number(3)})};
        assert!(s.valid_reason(Kind::PrReconcile,Reason::NativeRefused));
        if stopped {let at=Instant::now();e.cancel(Reason::UserCancelled,at);e.scope().read.revoke(at-Duration::from_millis(1));}
        e.operation_returned(&op,Reason::NativeRefused,Effect::FoundUnattributed,Some(s));c.returned(Ok(()));e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
        let out=e.status().unwrap();out.validate().unwrap();assert!(!e.positively_returned(&op));
        if stopped {assert!(out.result.is_none());assert_ne!(out.reason,Reason::NativeRefused);}
        else {assert_eq!(out.state,State::Refused);assert!(matches!(out.result,Some(p::dispatch::Snapshot::Operation(_))));}
    }
    let missing=serde_json::json!({"phase":"reconciled","marker":"b".repeat(32),"effect":"unresolved"});assert!(serde_json::from_value::<Snapshot>(missing).is_err());
    let null=serde_json::json!({"phase":"reconciled","marker":"b".repeat(32),"effect":"unresolved","observed":null});assert!(serde_json::from_value::<Snapshot>(null).unwrap().valid_for(Kind::PrReconcile));
}
#[test]
fn old_mutations_and_three_pending_families_share_same_full_book_and_failed_claim() {
    let doc=Arc::new(());let book=r::Inbox::new(id(2));let kinds=[Kind::RepositoryCreate,Kind::RepositoryPending,Kind::PrPending,Kind::FailedJobsPending];
    for n in 0..p::REQUEST_LIMIT {let kind=kinds[n%4];let grant=id(100+n as u64);book.allow(scope(&doc,kind),grant.clone()).unwrap();
        book.submit(p::Submit{origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(1000+n as u64)},grant_id:grant}).unwrap();
        let c=book.claim().unwrap().unwrap();let e=c.entry().clone();let op=arm(&e,true);
        if kind==Kind::RepositoryCreate{e.returned_native(&op,Reason::None,Effect::CreatedObserved);}else{e.operation_returned(&op,Reason::None,Effect::None,Some(Snapshot::Pending{rows:records()}));}
        c.returned(Ok(()));let history=e.claim_history().unwrap().unwrap();if n+1==p::REQUEST_LIMIT{drop(history);assert_eq!(e.status().unwrap().state,State::Unknown);}else{history.returned(Ok(())).unwrap();}
    }
    let rows=book.entries().unwrap();assert_eq!(rows.len(),32);assert_eq!(rows.iter().filter(|e|e.status().unwrap().result.is_some()).count(),23);
    assert!(book.allow(scope(&doc,Kind::PrPending),id(999)).is_err());assert!(rows.last().unwrap().pending());assert_eq!(book.entries().unwrap().len(),32);
}
