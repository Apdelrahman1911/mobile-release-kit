//! Same journal DATA, never a Store/NativeUse/ACK or native publication fixture.
use super::*;
use serde_json::json;

fn project(number:u8)->ProjectBinding {
    ProjectBinding {project_id:crate::service_protocol::Id::parse(&format!("{number:032x}")).unwrap(),
        canonical_root:"/inert/project".into(),device:1,inode:2}
}
fn review()->wire::Review {
    wire::Review::Branch(branch::Review {action:branch::Kind::Create,name:"next".into(),target_ref:"refs/heads/next".into(),
        expected_revision:"a".repeat(64),expected_reference_revision:"c".repeat(64),head:"1".repeat(40),
        branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)})
}
fn row(number:u8)->Row {Row::preparing(&project(number),"branch-original",&review()).unwrap()}
fn old_row()->Row {
    Row::preparing(&project(1),"file-original",&wire::Review::Files(wire::FileReview {
        action:wire::Kind::Stage,expected_revision:"a".repeat(64),paths:vec!["a.txt".into()],whole_index:false,
        head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)})).unwrap()
}
fn intent()->wire::Intent {
    let wire::Review::Branch(r)=review() else {panic!()};
    wire::Intent::Branch(branch::Intent {action:branch::Kind::Create,expected_revision:r.expected_revision,
        expected_reference_revision:r.expected_reference_revision,expected_ref:r.branch,expected_head:r.head.clone(),
        expected_index:r.expected_index,target_ref:r.target_ref,expected_target_absent:true,candidate_ref_oid:r.head})
}
fn snapshot(state:&State)->Snapshot {Snapshot {revision:Revision(3),bytes:state.bytes().unwrap()}}

#[test]
fn schema_one_read_is_byte_preserving_and_branch_apply_upgrades_same_rows_only() {
    let old=old_row();let mut state=State::empty();state.reserve(old.clone()).unwrap();
    let original=snapshot(&state);let mut decoded=State::decode(&original).unwrap();
    assert_eq!(decoded.bytes().unwrap(),original.bytes);assert_eq!(decoded.schema_version,1);
    assert!(!String::from_utf8(original.bytes).unwrap().contains("\"branch\""));
    decoded.reserve(row(2)).unwrap();assert_eq!(decoded.schema_version,2);
    assert!(decoded.rows[0]==old && decoded.rows[1]==row(2));
    let upgraded=snapshot(&decoded);assert_eq!(State::decode(&upgraded).unwrap().bytes().unwrap(),upgraded.bytes);
    assert!(decoded.rows[0].phase==Phase::Preparing && decoded.rows[0].outcome.is_none());
    // A same-project pending old operation is not overwritten by an upgrade.
    let mut pending=State::decode(&snapshot(&state)).unwrap();
    assert_eq!(pending.reserve(row(1)).err().unwrap().code,Error::RecoveryRequired);
    assert_eq!(pending.schema_version,1);assert!(pending.rows[0]==old);
}

#[test]
fn schema_two_is_closed_and_cannot_import_branch_data_as_a_legacy_row() {
    let mut state=State::empty();state.reserve(row(2)).unwrap();let good=snapshot(&state);
    for mutate in [
        (|v:&mut serde_json::Value|v["schemaVersion"]=json!(1)) as fn(&mut serde_json::Value),
        |v|v["schemaVersion"]=json!(3),
        |v|v["rows"][0]["branch"]["expectedTargetAbsent"]=json!(false),
        |v|v["rows"][0]["branch"]["targetRef"]=json!("refs/heads/main"),
        |v|v["rows"][0]["candidateIndex"]=json!("4".repeat(64)),
        |v|v["rows"][0]["branch"]["token"]=json!("not accepted"),
        |v|{v["rows"][0].as_object_mut().unwrap().remove("branch");},
    ] {
        let mut value:serde_json::Value=serde_json::from_slice(&good.bytes).unwrap();mutate(&mut value);
        let mut bytes=serde_json::to_vec(&value).unwrap();bytes.push(b'\n');
        assert_eq!(State::decode(&Snapshot {revision:good.revision,bytes}).err().unwrap().code,Error::RecoveryRequired);
    }
    let mut legacy=old_row();legacy.branch=row(2).branch;
    assert!(legacy.validate().is_err());
}

#[test]
fn branch_candidate_has_one_same_row_transition_and_no_fabricated_preparing_intent() {
    let original=row(2);assert!(!original.has_candidate() && original.intent().is_none());
    let good=intent();let mut candidate=original.clone();candidate.candidate(&good).unwrap();
    assert!(candidate.has_candidate() && candidate.same_original(&original));
    assert!(candidate.intent().unwrap()==good && candidate.candidate(&good).is_err());
    for (key,value) in [("expectedRevision",json!("f".repeat(64))),
        ("expectedReferenceRevision",json!("f".repeat(64))),("expectedIndex",json!("f".repeat(64))),
        ("expectedHead",json!("4".repeat(40))),("expectedRef",json!("refs/heads/other")),
        ("targetRef",json!("refs/heads/other")),("expectedTargetAbsent",json!(false)),("candidateRefOid",json!("4".repeat(40)))] {
        let mut value_bad=serde_json::to_value(&good).unwrap();value_bad[key]=value;
        let changed:wire::Intent=serde_json::from_value(value_bad).unwrap();let mut before=original.clone();
        assert!(before.candidate(&changed).is_err());assert!(before==original);
    }
    let mut changed=original.clone();changed.branch.as_mut().unwrap().target_ref="refs/heads/other".into();
    assert!(!changed.same_original(&original));
    let mut changed=original.clone();changed.branch.as_mut().unwrap().expected_reference_revision="f".repeat(64);
    assert!(!changed.same_original(&original));
}

#[test]
fn branch_candidate_or_recovery_never_becomes_a_retry_from_negative_readback() {
    for candidate in [false,true] {
        for recovery in [false,true] {
            let mut retained=row(2);if candidate {retained.candidate(&intent()).unwrap();}
            if recovery {retained.finish(Completion::RecoveryRequired).unwrap();}
            let mut state=State {schema_version:2,rows:vec![retained.clone()],..State::empty()};
            let decoded=State::decode(&snapshot(&state)).unwrap();assert!(decoded.rows[0]==retained);
            assert_eq!(state.reserve(row(2)).err().unwrap().code,Error::RecoveryRequired);
            assert!(state.rows[0]==retained);
        }
    }
    let mut candidate=row(2);candidate.candidate(&intent()).unwrap();
    assert!(candidate.clone().finish(Completion::Cancelled).is_err());
    assert!(candidate.clone().finish(Completion::Failed).is_err());
    assert!(row(2).finish(Completion::Succeeded).is_err());
}

#[test]
fn known_finished_branch_row_allows_only_new_explicit_same_snapshot_proposal() {
    let mut prior=row(2);prior.candidate(&intent()).unwrap();prior.finish(Completion::Succeeded).unwrap();
    let mut state=State {schema_version:2,rows:vec![prior],..State::empty()};
    let before=snapshot(&state);let mut next=row(2);next.review_digest="d".repeat(64);
    // Supervisor-local ID text can recur only after the prior original has
    // genuinely finished. This DATA call itself never supplies that witness.
    state.reserve(next.clone()).unwrap();assert!(state.rows[0]==next && !state.rows[0].has_candidate());
    assert!(snapshot_matches(&before,before.revision,&Snapshot {revision:before.revision,bytes:before.bytes.clone()}));
    assert!(!snapshot_matches(&before,Revision(before.revision.0+1),&before));
    assert!(!snapshot_matches(&before,before.revision,&snapshot(&state)));
}

#[test]
fn mixed_schema_two_keeps_one_project_row_and_fixed_capacity_without_private_inputs() {
    let mut state=State::empty();state.reserve(old_row()).unwrap();
    for n in (2..=MAX_ROWS as u8).rev() {state.reserve(row(n)).unwrap();}
    assert_eq!(state.rows.len(),MAX_ROWS);assert!(state.rows.windows(2).all(|p|p[0].project_id<p[1].project_id));
    assert!(state.reserve(row(33)).is_err());
    let bytes=state.bytes().unwrap();assert!(bytes.len()<=STATE_LIMIT);
    let text=String::from_utf8(bytes).unwrap();
    for field in ["message","identity","email","paths","root","diff","token","NativeUse"] {assert!(!text.contains(field));}
}
