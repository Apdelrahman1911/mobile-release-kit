//! Closed wire/representation DATA only. No native owner or provider is entered.
use super::*;
use crate::service_github_action_protocol as wire;
use crate::service_protocol::{Id, Settlement};
use serde_json::json;

fn id(n: u8) -> Id { Id::parse(&format!("{n:032x}")).unwrap() }
fn pending(n: usize, purpose: Purpose) -> Snapshot {
    Snapshot::Pending { rows: (1..=n).map(|i| Pending {
        marker: Hex::parse(&format!("{i:032x}")).unwrap(), run_id: Some(u64::MAX), purpose,
    }).collect() }
}
fn review(kind: Kind) -> wire::Review {
    let value = if matches!(kind, Kind::PreflightDispatch | Kind::ReleaseDispatch | Kind::CounterCreate) {
        json!({"kind":kind,"sessionId":"s".repeat(64),"expectedRevision":u32::MAX-1,
            "consentId":"a".repeat(32),"preparedSha256":"b".repeat(64)})
    } else if matches!(kind, Kind::PreflightObserve | Kind::ReleaseObserve | Kind::CounterReconcile) {
        let mut value=json!({"kind":kind,"sessionId":"s".repeat(64),"expectedRevision":u32::MAX-1,
            "marker":"a".repeat(32),"recordSha256":"b".repeat(64)});
        if kind != Kind::CounterReconcile { value["observe"]=json!("track"); value["runId"]=json!(u64::MAX.to_string()); }
        value
    } else { json!({"kind":kind,"sessionId":"s".repeat(64),"expectedRevision":u32::MAX-1,
        "requestSha256":"b".repeat(64)}) };
    serde_json::from_value(value).unwrap()
}

#[test]
fn twelve_new_references_are_closed_and_do_not_widen_cli_selection_or_consent() {
    let kinds=[Kind::PreflightPrepare,Kind::PreflightDispatch,Kind::PreflightPending,Kind::PreflightObserve,
        Kind::ReleasePrepare,Kind::ReleaseDispatch,Kind::ReleasePending,Kind::ReleaseObserve,
        Kind::CounterPrepare,Kind::CounterCreate,Kind::PublicationPending,Kind::CounterReconcile];
    for kind in kinds {
        let r=review(kind); assert!(r.valid()); assert!(r.retained_fits());
        let mut v=serde_json::to_value(&r).unwrap();
        assert!(serde_json::from_value::<wire::Selection>(v.clone()).is_err());
        assert_eq!(serde_json::from_value::<wire::Review>(v.clone()).unwrap(),r);
        assert_eq!(kind.consent(),format!("agent-{}-once-v1",v["kind"].as_str().unwrap()));
        for key in ["url","token","root","workflow","force"] {
            v[key]=json!("inert"); assert!(serde_json::from_value::<wire::Review>(v.clone()).is_err());
            v.as_object_mut().unwrap().remove(key);
        }
        let mut bad=v.clone(); bad["expectedRevision"]=json!(0);
        assert!(!serde_json::from_value::<wire::Review>(bad).unwrap().valid());
        assert_eq!(kind.mutation(),matches!(kind,Kind::PreflightDispatch|Kind::ReleaseDispatch|Kind::CounterCreate));
        assert!(!wire::Effect::PotentiallyApplied.valid_for(kind) || kind.mutation());
        assert_eq!(kind.initial_effect(),if kind.mutation(){wire::Effect::NotSent}else{wire::Effect::None});
    }
    assert!(wire::Effect::Unresolved.valid_for(Kind::CounterReconcile));
    assert!(!wire::Effect::CounterObserved.valid_for(Kind::PreflightPrepare));
    assert!(!wire::Effect::Accepted.valid_for(Kind::ReleasePrepare));
}

#[test]
fn exact_record_reference_requires_mode_bound_run_and_no_fabricated_consent() {
    let v=json!({"sessionId":"session-a","expectedRevision":4,"marker":"a".repeat(32),
        "recordSha256":"b".repeat(64),"observe":"reconcile","runId":null});
    assert!(serde_json::from_value::<RecordReference>(v.clone()).unwrap().valid());
    for bad in [json!("0"),json!("01"),json!("18446744073709551616"),json!("3\n"),json!(3)] {
        let mut b=v.clone();b["observe"]=json!("track");b["runId"]=bad;
        assert!(serde_json::from_value::<RecordReference>(b).map_or(true,|v|!v.valid()));
    }
    let mut b=v.clone();b["runId"]=json!("3");assert!(!serde_json::from_value::<RecordReference>(b).unwrap().valid());
    let mut b=v.clone();b.as_object_mut().unwrap().remove("runId");assert!(serde_json::from_value::<RecordReference>(b).is_err());
    let mut b=v;b["consentId"]=json!("c".repeat(32));assert!(serde_json::from_value::<RecordReference>(b).is_err());
}

#[test]
fn compact_binary_cells_roundtrip_and_reject_noncanonical_ids() {
    let v=Snapshot::Counter { marker:Hex::parse(&"a".repeat(32)).unwrap(),
        commit_sha:Hex::parse(&"b".repeat(40)).unwrap(),
        ledger_id:LedgerId::parse("12345678-1234-4234-9234-123456789abc").unwrap(),
        genesis_sha256:Hex::parse(&"c".repeat(64)).unwrap() };
    assert!(v.valid_for(Kind::CounterCreate));assert!(v.valid_for(Kind::CounterReconcile));
    let bytes=serde_json::to_vec(&v).unwrap();assert_eq!(serde_json::from_slice::<Snapshot>(&bytes).unwrap(),v);
    assert!(v.allocated().unwrap() <= SNAPSHOT_BACKING);
    for id in ["12345678-1234-1234-9234-123456789abc","12345678-1234-4234-7234-123456789abc",
        "12345678_1234-4234-9234-123456789abc","12345678-1234-4234-9234-123456789ABC"] {assert!(LedgerId::parse(id).is_none());}
    assert!(Hex::<20>::parse(&"B".repeat(40)).is_none());
    assert!(!v.valid_for(Kind::CounterPrepare));
}

#[test]
fn full_sixty_four_record_capacity_and_outer_access_fit_without_truncation() {
    let s=pending(ROWS,Purpose::Preflight);
    assert!(s.valid_for(Kind::PreflightPending));
    assert!(s.allocated().unwrap() <= SNAPSHOT_BACKING);
    let round:Snapshot=serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    assert_eq!(s,round); assert!(round.allocated().unwrap() <= SNAPSHOT_BACKING);
    let status=wire::Status { origin:wire::Query{project_id:id(1),service_instance:id(2),request_id:id(4)},
        grant_id:id(3),review:review(Kind::PreflightPending),revision:u32::MAX-1,state:wire::State::Complete,
        settlement:Settlement::Settled,operation_id:Some(format!("github-preflight-{}",u64::MAX)),reason:wire::Reason::None,
        effect:wire::Effect::None,never_admitted:false,do_not_replay:true,snapshot:None,result:Some(s) };
    status.validate().unwrap();
    let access=wire::Access { service_instance:Some(id(2)),project_id:Some(id(1)),grant_id:Some(id(3)),
        review:Some(status.review.clone()),enabled:false,remaining_ms:0,consumed:true,pending:false,
        unknown:false,status:Some(status) };
    access.validate().unwrap();
    let main=wire::activity::MainAccess {access,permission_revision:wire::activity::PermissionRevision(u64::MAX)};
    let encoded=serde_json::to_vec(&main).unwrap();assert!(encoded.len()<=RESPONSE_LIMIT,"{}",encoded.len());
    assert!(!pending(ROWS+1,Purpose::Preflight).valid_for(Kind::PreflightPending));
    assert!(serde_json::from_slice::<Snapshot>(&serde_json::to_vec(&pending(ROWS+1,Purpose::Preflight)).unwrap()).is_err());
}

#[test]
fn compact_snapshot_rejects_real_capacity_growth_cross_kind_and_duplicate_rows() {
    let mut s=pending(1,Purpose::Release);
    assert!(s.valid_for(Kind::ReleasePending));assert!(!s.valid_for(Kind::PreflightPending));
    if let Snapshot::Pending{rows}=&mut s {rows.push(rows[0]);}
    assert!(!s.valid_for(Kind::ReleasePending));
    if let Snapshot::Pending{rows}=&mut s {rows.truncate(1);rows.reserve_exact(1024);}
    assert!(!s.valid_for(Kind::ReleasePending)); // len1 cannot hide backing for1025
    let v=json!({"type":"prepared","marker":"a".repeat(32),"preparedSha256":"b".repeat(64),
        "sourceSha":"c".repeat(40),"platform":null,"stage":null});
    let s:Snapshot=serde_json::from_value(v.clone()).unwrap();assert!(s.valid_for(Kind::CounterPrepare));
    assert!(!s.valid_for(Kind::PreflightPrepare));
    let mut b=v;b.as_object_mut().unwrap().remove("stage");assert!(serde_json::from_value::<Snapshot>(b).is_err());
    assert!(serde_json::from_str::<Snapshot>(r#"{"type":"pending","rows":[],"url":"inert"}"#).is_err());
}
