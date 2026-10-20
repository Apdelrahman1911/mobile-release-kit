//! Canonical SAME-row DATA tests; no Store/native-use/current owner or IO.
use super::*;
use crate::git_switch_protocol::tests as data;
use serde_json::json;

fn project(number:u8)->ProjectBinding {ProjectBinding {project_id:crate::service_protocol::Id::parse(&format!("{number:032x}")).unwrap(),
    canonical_root:"/inert/project".into(),device:1,inode:2}}
fn row(number:u8)->Row {Row::preparing(&project(number),"switch-original",&wire::Review::Switch(data::review())).unwrap()}
fn intent()->wire::Intent {wire::Intent::Switch(data::intent())}
fn old(number:u8)->Row {Row::preparing(&project(number),"old-original",&wire::Review::Files(wire::FileReview {
    action:wire::Kind::Stage,expected_revision:"a".repeat(64),paths:vec!["a.txt".into()],whole_index:false,
    head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)})).unwrap()}
fn created(number:u8)->Row {Row::preparing(&project(number),"branch-original",&wire::Review::Branch(branch::Review {
    action:branch::Kind::Create,name:"created".into(),target_ref:"refs/heads/created".into(),expected_revision:"a".repeat(64),
    expected_reference_revision:"c".repeat(64),head:"1".repeat(40),branch:Some("refs/heads/main".into()),
    expected_index:"2".repeat(64),review_digest:"b".repeat(64)})).unwrap()}
fn snapshot(state:&State)->Snapshot {Snapshot {revision:Revision(3),bytes:state.bytes().unwrap()}}

#[test]
fn schema_one_and_two_reads_preserve_bytes_and_switch_preparing_alone_upgrades_same_envelope() {
    let mut state=State::empty();state.reserve(old(1)).unwrap();let v1=snapshot(&state);
    assert_eq!(State::decode(&v1).unwrap().bytes().unwrap(),v1.bytes);
    assert!(!String::from_utf8(v1.bytes.clone()).unwrap().contains("\"switch\""));
    state.reserve(created(2)).unwrap();let v2=snapshot(&state);assert_eq!(state.schema_version,2);
    assert_eq!(State::decode(&v2).unwrap().bytes().unwrap(),v2.bytes);
    let prior=state.rows.clone();state.reserve(row(3)).unwrap();assert_eq!(state.schema_version,3);
    assert!(state.rows[..2]==prior);let v3=snapshot(&state);assert_eq!(State::decode(&v3).unwrap().bytes().unwrap(),v3.bytes);
    state.reserve(created(4)).unwrap();assert_eq!(state.schema_version,3); // No downgrade by later create.
    for before in [v1,v2,v3] {
        let mut current=State::decode(&before).unwrap();assert!(current.reserve(row(1)).is_err());
        assert_eq!(current.bytes().unwrap(),before.bytes); // Pending local operation never replaced.
    }
}

#[test]
fn schema_three_is_closed_and_switch_candidate_requires_paired_index_metadata_and_original_ref() {
    let mut state=State::empty();state.reserve(row(1)).unwrap();let original=snapshot(&state);
    for change in [
        (|v:&mut serde_json::Value|v["schemaVersion"]=json!(2)) as fn(&mut serde_json::Value),
        |v|v["schemaVersion"]=json!(4),
        |v|{v["rows"][0].as_object_mut().unwrap().remove("switch");},
        |v|v["rows"][0]["switch"]["targetRef"]=json!("refs/heads/main"),
        |v|v["rows"][0]["switch"]["targetOid"]=json!("bad"),
        |v|v["rows"][0]["switch"]["log"]["originalKind"]=json!("symlink"),
        |v|v["rows"][0]["candidateIndex"]=json!("d".repeat(64)),
        |v|v["rows"][0]["switch"]["force"]=json!(false),
    ] {
        let mut v:serde_json::Value=serde_json::from_slice(&original.bytes).unwrap();change(&mut v);
        let bytes=data::raw(v);assert_eq!(State::decode(&Snapshot {revision:original.revision,bytes}).err().unwrap().code,Error::RecoveryRequired);
    }
    let mut legacy=old(1);legacy.switch=row(1).switch;assert!(legacy.validate().is_err());
    let mut pending=row(1);assert!(pending.intent().is_none());pending.candidate(&intent()).unwrap();assert!(pending.intent()==Some(intent()));
    pending.switch.as_mut().unwrap().candidate=None;assert!(pending.validate().is_err());
}

#[test]
fn switch_candidate_binds_whole_preparing_row_and_accepts_only_one_amendment() {
    let original=row(1);let mut next=original.clone();next.candidate(&intent()).unwrap();
    assert!(next.same_original(&original) && next.has_candidate());assert!(next.candidate(&intent()).is_err());
    for (field,value) in [("expectedRevision",json!("f".repeat(64))),("expectedReferenceRevision",json!("f".repeat(64))),
        ("expectedHead",json!("7".repeat(40))),("expectedIndex",json!("f".repeat(64))),
        ("targetRef",json!("refs/heads/other")),("targetOid",json!("7".repeat(40))),("originalLog",json!("f".repeat(64))),
        ("candidateHead",json!("f".repeat(64)))] {
        let mut v=serde_json::to_value(intent()).unwrap();v[field]=value;let changed:wire::Intent=serde_json::from_value(v).unwrap();
        let mut current=original.clone();assert!(current.candidate(&changed).is_err());assert!(current==original);
    }
    let mut other=original.clone();other.switch.as_mut().unwrap().files[0].source_sha256="f".repeat(64);
    assert!(!other.same_original(&original));
    other=original.clone();other.switch.as_mut().unwrap().log.enabled=false;assert!(!other.same_original(&original));
}

#[test]
fn switch_pending_partial_or_unknown_outcome_never_recycles_and_success_needs_original_candidate() {
    for candidate in [false,true] {for recovery in [false,true] {
        let mut retained=row(1);if candidate {retained.candidate(&intent()).unwrap();}
        if recovery {retained.finish(Completion::RecoveryRequired).unwrap();}
        let mut state=State {schema_version:3,protocol:PROTOCOL.into(),rows:vec![retained.clone()]};
        let before=snapshot(&state);assert!(State::decode(&before).unwrap().rows[0]==retained);
        assert_eq!(state.reserve(row(1)).err().unwrap().code,Error::RecoveryRequired);
        assert_eq!(state.bytes().unwrap(),before.bytes);
    }}
    let mut retained=row(1);retained.candidate(&intent()).unwrap();
    assert!(retained.clone().finish(Completion::Failed).is_err());assert!(retained.clone().finish(Completion::Cancelled).is_err());
    assert!(row(1).finish(Completion::Succeeded).is_err());
}

#[test]
fn same_text_id_requires_known_finished_and_fresh_original_snapshot_never_retry_of_old_switch() {
    let mut prior=row(1);prior.candidate(&intent()).unwrap();
    let details=switch::FinalData {effect_phase:"index-returned".into(),retained_paths:vec![]};
    prior.finish_with_switch(Completion::Succeeded,Some(&details)).unwrap();
    let mut state=State {schema_version:3,protocol:PROTOCOL.into(),rows:vec![prior]};let before=snapshot(&state);
    let mut proposal=row(1);proposal.review_digest="8".repeat(64);state.reserve(proposal.clone()).unwrap();
    assert!(state.rows[0]==proposal && !state.rows[0].has_candidate());
    assert!(!snapshot_matches(&before,before.revision,&snapshot(&state)));
    assert!(!snapshot_matches(&before,Revision(before.revision.0+1),&before));
    // An existing NativeUse/live owner still must supply this actual CAS; this
    // DATA test does not confer it or create a resumable operation from a row.
}

#[test]
fn final_cas_detail_is_bounded_historical_data_and_never_amends_pending_or_unknown_rows() {
    let mut original=row(1);original.candidate(&intent()).unwrap();
    let details=switch::FinalData {effect_phase:"head-returned".into(),
        retained_paths:vec![".git/mrk-git-fixture/HEAD".into(),".git/mrk-git-fixture/index".into()]};
    assert!(original.clone().finish(Completion::Succeeded).is_err());
    assert!(original.clone().finish_with_switch(Completion::Succeeded,Some(&details)).is_err());
    let mut bad=original.clone();bad.switch.as_mut().unwrap().final_state=Some(details.clone());
    assert!(bad.validate().is_err()); // Candidate rows cannot acquire final details from a read.
    let mut finished=original.clone();finished.finish_with_switch(Completion::RecoveryRequired,Some(&details)).unwrap();
    assert!(finished.switch.as_ref().unwrap().final_state.as_ref()==Some(&details));
    let state=State {schema_version:3,protocol:PROTOCOL.into(),rows:vec![finished.clone()]};
    let before=snapshot(&state);let mut restarted=State::decode(&before).unwrap();
    assert!(restarted.rows[0]==finished && !restarted.rows[0].replaceable());
    assert!(restarted.reserve(row(1)).is_err());assert_eq!(restarted.bytes().unwrap(),before.bytes);
    assert!(finished.finish_with_switch(Completion::RecoveryRequired,Some(&details)).is_err());
    for paths in [vec!["/unowned/path".into()],vec![".git/mrk-git-fixture/index".into();6]] {
        let mut bad=details.clone();bad.retained_paths=paths;assert!(!bad.valid());
        assert!(original.clone().finish_with_switch(Completion::RecoveryRequired,Some(&bad)).is_err());
    }
    // No acknowledged final CAS means the original snapshot remains pending;
    // this test never rewrites it on the strength of the proposed detail.
    assert!(original.switch.as_ref().unwrap().final_state.is_none() && original.phase==Phase::Candidate);
}
