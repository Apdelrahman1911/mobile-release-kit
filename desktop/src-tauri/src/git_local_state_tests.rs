//! Bounded journal DATA only. No Store open, NativeUse, process or native proof.
use super::*;
use serde_json::json;

fn project(number: u8) -> ProjectBinding {
    ProjectBinding { project_id:crate::service_protocol::Id::parse(&format!("{number:032x}")).unwrap(), canonical_root:"/inert/project".into(), device:1, inode:2 }
}
fn review(kind:wire::Kind) -> wire::Review {
    wire::Review::Files(wire::FileReview { action:kind, expected_revision:"a".repeat(64), paths:vec!["a.txt".into()],
        whole_index:kind==wire::Kind::Commit, head:Some("1".repeat(40)), branch:Some("refs/heads/main".into()),
        expected_index:"2".repeat(64), review_digest:"b".repeat(64) })
}
fn row(number:u8, kind:wire::Kind) -> Row { Row::preparing(&project(number),&format!("operation-{number}"),&review(kind)).unwrap() }
fn intent(row:&Row) -> wire::Intent {
    let wire::Intent::Files(original)=row.intent().unwrap() else {panic!()};
    wire::Intent::Files(wire::FileIntent { candidate_index:(row.action!=wire::Kind::Commit).then(||"3".repeat(64)),
        candidate_commit:(row.action==wire::Kind::Commit).then(||"4".repeat(40)), ..original })
}
fn snapshot(state:&State) -> Snapshot { Snapshot {revision:Revision(3),bytes:state.bytes().unwrap()} }

#[test]
fn empty_namespace_is_only_original_revision_zero_not_absent_as_empty() {
    assert!(State::decode(&Snapshot {revision:Revision(0),bytes:vec![]}).unwrap().rows.is_empty());
    assert_eq!(State::decode(&Snapshot {revision:Revision(1),bytes:vec![]}).err().unwrap().code,Error::RecoveryRequired);
    let mut state=State::empty();state.reserve(row(1,wire::Kind::Stage)).unwrap();
    let mut value=snapshot(&state);value.revision=Revision(0);assert!(State::decode(&value).is_err());
}

#[test]
fn canonical_closed_bytes_never_persist_draft_diff_source_or_credential() {
    let mut state=State::empty();state.reserve(row(1,wire::Kind::Commit)).unwrap();
    let before=snapshot(&state);let after=State::decode(&before).unwrap();assert_eq!(after.bytes().unwrap(),before.bytes);
    let data=String::from_utf8(before.bytes.clone()).unwrap();
    for name in ["message","email","diff","paths","root","token","nativeUse"] {assert!(!data.contains(name));}
    for bytes in [before.bytes[..before.bytes.len()-1].to_vec(),b"{}\n".to_vec(),b"{\"schemaVersion\":1,\"schemaVersion\":1}\n".to_vec()] {
        assert!(State::decode(&Snapshot {revision:Revision(3),bytes}).is_err());
    }
    let mut extra:serde_json::Value=serde_json::from_slice(&before.bytes).unwrap();extra["credential"]=json!("not accepted");
    let mut bytes=serde_json::to_vec(&extra).unwrap();bytes.push(b'\n');
    assert!(State::decode(&Snapshot {revision:Revision(3),bytes}).is_err());
}

#[test]
fn stable_native_project_id_is_not_renderer_alias_or_zero() {
    for id in ["runtime-alias".to_owned(),"0".repeat(32),"A".repeat(32)] {
        assert!(crate::service_protocol::Id::parse(&id).is_err());
        let mut r=row(1,wire::Kind::Stage);r.project_id=id;assert!(r.validate().is_err());
    }
    let mut p=project(1);p.device=0;assert!(Row::preparing(&p,"operation-1",&review(wire::Kind::Stage)).is_err());
    let mut p=project(1);p.canonical_root="relative".into();assert!(Row::preparing(&p,"operation-1",&review(wire::Kind::Stage)).is_err());
}

#[test]
fn same_row_candidate_binds_all_reviewed_old_fields_and_is_once_only() {
    let original=row(1,wire::Kind::Stage);let good=intent(&original);
    for name in ["expectedRef","expectedHead","expectedIndex","expectedRevision"] {
        let mut value=serde_json::to_value(&good).unwrap();
        value[name]=json!(if name=="expectedRef" {"refs/heads/other".into()} else if name=="expectedHead" {"f".repeat(40)} else {"f".repeat(64)});
        let changed:wire::Intent=serde_json::from_value(value).unwrap();assert!(original.clone().candidate(&changed).is_err());
    }
    let mut value=original.clone();value.candidate(&good).unwrap();assert!(value.same_original(&original));
    assert!(value.candidate(&good).is_err());assert!(value.has_candidate());
    let mut wrong=good;let wire::Intent::Files(file)=&mut wrong else {panic!()};file.candidate_commit=Some("4".repeat(40));assert!(original.clone().candidate(&wrong).is_err());
}

#[test]
fn pending_and_unknown_restart_rows_never_authorize_retry() {
    for candidate in [false,true] {
        let mut original=row(1,wire::Kind::Stage);if candidate {original.candidate(&intent(&original)).unwrap();}
        for recovery in [false,true] {
            let mut retained=original.clone();if recovery {retained.finish(Completion::RecoveryRequired).unwrap();}
            let state=State {rows:vec![retained],..State::empty()};let mut decoded=State::decode(&snapshot(&state)).unwrap();
            let mut next=row(1,wire::Kind::Stage);next.operation_id="explicit-new-operation".into();
            assert_eq!(decoded.reserve(next).err().unwrap().code,Error::RecoveryRequired);
        }
    }
}

#[test]
fn candidate_cannot_become_cancelled_or_failed_no_effect_by_negative_readback() {
    for kind in [wire::Kind::Stage,wire::Kind::Unstage,wire::Kind::Commit] {
        let mut original=row(1,kind);assert!(original.clone().finish(Completion::Succeeded).is_err());
        original.candidate(&intent(&original)).unwrap();
        assert!(original.clone().finish(Completion::Failed).is_err());
        assert!(original.clone().finish(Completion::Cancelled).is_err());
        original.finish(Completion::Succeeded).unwrap();assert!(original.replaceable());
        assert!(original.finish(Completion::Succeeded).is_err());
    }
}

#[test]
fn one_row_per_project_preserves_other_projects_and_bounded_sorted_capacity() {
    let mut state=State::empty();for n in (1..=MAX_ROWS as u8).rev() {state.reserve(row(n,wire::Kind::Stage)).unwrap();}
    assert_eq!(state.rows.len(),MAX_ROWS);assert!(state.rows.windows(2).all(|p|p[0].project_id<p[1].project_id));
    assert!(state.reserve(row(33,wire::Kind::Stage)).is_err());
    let old_other=state.rows[1].clone();state.rows[0].finish(Completion::Cancelled).unwrap();
    let mut replacement=row(1,wire::Kind::Unstage);replacement.operation_id="new-operation-1".into();
    state.reserve(replacement).unwrap();assert!(state.rows[1]==old_other && state.rows.len()==MAX_ROWS);
    let mut duplicate=state.rows[0].clone();duplicate.project_id=project(40).project_id.as_str().to_owned();
    assert!(state.reserve(duplicate).is_err());
}

#[test]
fn decoded_row_is_not_same_original_across_project_action_or_operation() {
    let original=row(1,wire::Kind::Stage);
    let mut other=original.clone();other.project_id=project(2).project_id.as_str().to_owned();assert!(!other.same_original(&original));
    let mut other=original.clone();other.operation_id="another-original".into();assert!(!other.same_original(&original));
    let mut other=original.clone();other.action=wire::Kind::Unstage;assert!(!other.same_original(&original));
    let mut state=State::empty();state.reserve(original).unwrap();let mut duplicate=state.rows[0].clone();
    duplicate.operation_id="different".into();state.rows.push(duplicate);assert!(state.bytes().is_err());
}

#[test]
fn supervisor_text_reuse_requires_known_finished_row_and_fresh_exact_snapshot() {
    let original=row(1,wire::Kind::Stage);
    for candidate in [false,true] {
        let mut pending=original.clone();if candidate {pending.candidate(&intent(&pending)).unwrap();}
        for recovery in [false,true] {
            let mut retained=pending.clone();if recovery {retained.finish(Completion::RecoveryRequired).unwrap();}
            let mut state=State {rows:vec![retained],..State::empty()};
            assert_eq!(state.reserve(original.clone()).err().unwrap().code,Error::RecoveryRequired);
        }
    }
    let mut finished=original.clone();finished.finish(Completion::Cancelled).unwrap();
    let mut state=State {rows:vec![finished],..State::empty()};
    // DATA proposal for a NEW explicit admission, not execution/replay of the
    // old row. Same text is legitimate after Supervisor process restart.
    let mut next=original.clone();next.expected_revision="c".repeat(64);next.review_digest="d".repeat(64);
    state.reserve(next.clone()).unwrap();assert!(state.rows[0]==next);
    let mut other=row(2,wire::Kind::Stage);other.operation_id=original.operation_id.clone();
    state.reserve(other).unwrap();assert_eq!(state.rows.len(),2);
    let held=snapshot(&state);let exact=Snapshot {revision:held.revision,bytes:held.bytes.clone()};
    assert!(snapshot_matches(&held,held.revision,&exact));
    assert!(!snapshot_matches(&held,Revision(held.revision.0+1),&exact));
    assert!(!snapshot_matches(&held,held.revision,&Snapshot {revision:Revision(held.revision.0+1),bytes:held.bytes.clone()}));
    assert!(!snapshot_matches(&held,held.revision,&Snapshot {revision:held.revision,bytes:vec![]}));
}
