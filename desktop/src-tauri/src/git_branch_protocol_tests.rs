//! Closed DATA regression tables. No native source, Store, process, token or
//! publication/finality witness is created by any of these fixtures.
use super::*;
use crate::git_local_protocol as local;
use serde_json::json;

fn selected() -> Action {
    Action { kind: Kind::Create, expected_revision: "a".repeat(64),
        expected_reference_revision: "c".repeat(64), name: "next".into() }
}
fn review() -> Review {
    Review { action: Kind::Create, name: "next".into(), target_ref: "refs/heads/next".into(),
        expected_revision: "a".repeat(64), expected_reference_revision: "c".repeat(64),
        head: "1".repeat(40), branch: Some("refs/heads/main".into()),
        expected_index: "2".repeat(64), review_digest: "b".repeat(64) }
}
fn intent() -> Intent {
    let r = review();
    Intent { action: Kind::Create, expected_revision: r.expected_revision,
        expected_reference_revision: r.expected_reference_revision, expected_ref: r.branch,
        expected_head: r.head.clone(), expected_index: r.expected_index,
        target_ref: r.target_ref, expected_target_absent: true, candidate_ref_oid: r.head }
}
fn native() -> local::Native {
    let file = |uid,mode| local::Snapshot {
        identity: (1,2,mode,uid,1001,1,12,123,456), sha256: "2".repeat(64) };
    local::Native { uid:1001,gid:1001,root:"/inert/project".into(),
        directories: local::Directories { root:(1,2,0o40700,1001,1001),
            git:(1,3,0o40700,1001,1001), objects:(1,4,0o40700,1001,1001) },
        tool:file(0,0o100755), files:local::Files { head:file(1001,0o100600),
            config:file(1001,0o100600), index:Some(file(1001,0o100600)) } }
}
fn request(phase:local::Phase) -> local::Request {
    local::Request::from_original("branch-fixture",&local::Action::Branch(selected()),
        &local::Context {project_id:"runtime-alias".into(),generation:1,revision:"document-2".into()},
        &native(),local::Clock {work_end_ns:100_000_000_000,hard_end_ns:110_000_000_000},
        (phase==local::Phase::Apply).then(||local::ApplyBinding {
            review:local::Review::Branch(review()),journal_revision:4})).unwrap()
}
fn raw(value:Value) -> Vec<u8> {
    let mut bytes=serde_json::to_vec(&value).unwrap();bytes.push(b'\n');bytes
}
fn candidate_value(r:&local::Request) -> Value {
    json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
        "reviewDigest":"b".repeat(64),"intent":intent()})
}
fn terminal(r:&local::Request) -> Value {
    json!({"protocol":local::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,
        "phase":r.phase,"action":"branch-create","status":"ok","reason":null,
        "result":null,"publication":"not-reported","firstFailureNs":null,
        "cleanupEndNs":r.clock.hard_end_ns})
}
fn list() -> Value {
    json!({"revision":"a".repeat(64),"referenceRevision":"c".repeat(64),"head":"1".repeat(40),
        "branch":"refs/heads/main","branches":[{"ref":"refs/heads/main","oid":"1".repeat(40)}],
        "basis":"local-refs-no-fetch"})
}

#[test]
fn branch_create_command_is_exact_tagged_name_and_no_revision_or_command_input() {
    let good=json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":selected()});
    let local::Command::Prepare(parsed)=local::decode_command("git_local_prepare",&raw(good.clone())).unwrap()
        else {panic!()};
    assert!(parsed.action.kind()==local::Kind::BranchCreate && parsed.action.valid());
    assert_eq!(serde_json::to_value(parsed.action.public()).unwrap(),json!(selected()));
    for key in ["paths","message","identity","force","startPoint","argv","ref","upstream"] {
        let mut bad=good.clone();bad["action"][key]=json!(null);
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    for key in ["expectedRevision","expectedReferenceRevision","name"] {
        let mut bad=good.clone();bad["action"].as_object_mut().unwrap().remove(key);
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    for name in ["","-next","a..b","a.lock","a/.b","a//b","a/","a@{b","a b","é"] {
        let mut bad=good.clone();bad["action"]["name"]=json!(name);
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    assert!(!name(&"a".repeat(256)) && !name(&vec!["a";17].join("/")));
    // The existing file action does not become a permissive optional-field bag.
    let mut old=good;old["action"]=json!({"kind":"stage","expectedRevision":"a".repeat(64),
        "paths":["a.txt"],"message":null,"identity":null});
    assert!(local::decode_command("git_local_prepare",&raw(old.clone())).is_ok());
    old["action"].as_object_mut().unwrap().remove("identity");
    assert!(local::decode_command("git_local_prepare",&raw(old)).is_err());
}

#[test]
fn branches_read_requires_current_observation_and_has_no_remote_options() {
    let action=read::Action {kind:read::Kind::Branches,expected_revision:Some("a".repeat(64)),paths:vec![],staged:false};
    let value=json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":action});
    assert!(matches!(read::decode_command("git_read_start",&raw(value.clone())).unwrap(),read::Command::Start(_)));
    read::validate_result(&action,&list()).unwrap();
    for (key,v) in [("expectedRevision",Value::Null),("paths",json!(["a.txt"])),("staged",json!(true)),("fetch",json!(false))] {
        let mut bad=value.clone();bad["action"][key]=v;
        assert!(read::decode_command("git_read_start",&raw(bad)).is_err());
    }
}

#[test]
fn branch_list_is_bounded_complete_sorted_and_binds_current_branch_oid() {
    let revision="a".repeat(64);let good=list();validate_list(Some(&revision),&good).unwrap();
    assert!(validate_list(None,&good).is_err());
    assert!(validate_list(Some(&"f".repeat(64)),&good).is_err());
    for (key,value) in [("referenceRevision",json!("wrong")),("basis",json!("live")),
        ("head",json!("4".repeat(40))),("branch",json!("refs/heads/missing")),("url",json!("unused"))] {
        let mut bad=good.clone();bad[key]=value;assert!(validate_list(Some(&revision),&bad).is_err());
    }
    for rows in [
        json!([{"ref":"refs/heads/main","oid":"1".repeat(40),"message":"not accepted"}]),
        json!([{"ref":"refs/heads/main","oid":"1".repeat(40)},{"ref":"refs/heads/main","oid":"1".repeat(40)}]),
        json!([{"ref":"refs/heads/z","oid":"1".repeat(40)},{"ref":"refs/heads/main","oid":"1".repeat(40)}]),
        json!([{"ref":"refs/heads/main","oid":"1".repeat(40)},{"ref":"refs/heads/z","oid":"1".repeat(64)}]),
        json!([{"ref":"refs/tags/main","oid":"1".repeat(40)}]),
    ] { let mut bad=good.clone();bad["branches"]=rows;assert!(validate_list(Some(&revision),&bad).is_err()); }
    let mut oversized=good;oversized["branch"]=Value::Null;
    oversized["branches"]=json!((0..257).map(|n|json!({"ref":format!("refs/heads/b{n:03}"),"oid":"1".repeat(40)})).collect::<Vec<_>>());
    assert!(validate_list(Some(&revision),&oversized).is_err());
}

#[test]
fn unborn_list_does_not_authorize_create_and_detached_create_does_not_attach() {
    let mut value=list();value["head"]=Value::Null;value["branches"]=json!([]);
    validate_list(Some(&"a".repeat(64)),&value).unwrap();
    value["branch"]=Value::Null;assert!(validate_list(Some(&"a".repeat(64)),&value).is_err());
    let mut r=review();r.head.clear();assert!(!r.valid());
    r=review();r.branch=None;assert!(r.valid() && r.matches(&selected()));
    let mut i=intent();i.expected_ref=None;assert!(i.matches(&r));
    i.expected_ref=Some(r.target_ref.clone());assert!(!i.valid());
}

#[test]
fn branch_prepare_returns_ref_review_only_never_a_fabricated_diff() {
    let r=request(local::Phase::Prepare);let mut value=terminal(&r);
    value["result"]=json!({"review":review()});
    let parsed=r.terminal(&raw(value.clone()),None).unwrap();
    assert!(parsed.review().unwrap()==local::Review::Branch(review()));
    for key in ["diff","paths","wholeIndex"] {
        let mut bad=value.clone();bad["result"][key]=json!(null);
        assert!(r.terminal(&raw(bad),None).is_err());
    }
    for (key,changed) in [("name",json!("other")),("targetRef",json!("refs/heads/other")),
        ("expectedReferenceRevision",json!("f".repeat(64))),("expectedRevision",json!("f".repeat(64)))] {
        let mut bad=value.clone();bad["result"]["review"][key]=changed;
        assert!(r.terminal(&raw(bad),None).is_err());
    }
    value["result"]["review"].as_object_mut().unwrap().remove("branch");
    assert!(r.terminal(&raw(value),None).is_err());
}

#[test]
fn branch_candidate_binds_original_head_index_ref_inventory_absence_and_name() {
    let r=request(local::Phase::Apply);let good=candidate_value(&r);
    let c=r.candidate(&raw(good.clone())).unwrap();r.ack(&c,5).unwrap();
    assert!(r.ack(&c,4).is_err() && r.ack(&c,6).is_err());
    for (key,value) in [("expectedRevision",json!("f".repeat(64))),
        ("expectedReferenceRevision",json!("f".repeat(64))),("expectedHead",json!("4".repeat(40))),
        ("expectedIndex",json!("f".repeat(64))),("expectedRef",json!("refs/heads/other")),
        ("targetRef",json!("refs/heads/other")),("expectedTargetAbsent",json!(false)),
        ("candidateRefOid",json!("4".repeat(40))),("candidateIndex",Value::Null),("candidateCommit",Value::Null)] {
        let mut bad=good.clone();bad["intent"][key]=value;
        assert!(r.candidate(&raw(bad)).is_err());
    }
    assert!(request(local::Phase::Prepare).candidate(&raw(good)).is_err());
}

#[test]
fn branch_success_needs_exact_branch_publication_and_preserves_current_head_branch() {
    let r=request(local::Phase::Apply);let c=r.candidate(&raw(candidate_value(&r))).unwrap();
    let mut value=terminal(&r);value["publication"]=json!("branch-ref-returned");
    value["result"]=json!({"operationId":r.id,"action":"branch-create","state":"succeeded","settlement":"settled",
        "reason":null,"intent":c.intent,"observation":{"revision":"e".repeat(64),"head":"1".repeat(40),
        "branch":"refs/heads/main","unborn":false,"detached":false,"changes":[],"remotes":[],"restrictions":[]}});
    assert!(r.terminal(&raw(value.clone()),Some(&c)).unwrap().child_declared_settled());
    assert!(r.terminal(&raw(value.clone()),None).is_err());
    for p in ["not-reported","index-returned","ref-returned"] {
        let mut bad=value.clone();bad["publication"]=json!(p);assert!(r.terminal(&raw(bad),Some(&c)).is_err());
    }
    for (key,v) in [("head",json!("4".repeat(40))),("branch",json!("refs/heads/next"))] {
        let mut bad=value.clone();bad["result"]["observation"][key]=v;
        assert!(r.terminal(&raw(bad),Some(&c)).is_err());
    }
    // This only validates child DATA; no native original receipt exists here.
}

#[test]
fn branch_specific_refusal_is_not_an_old_action_or_unknown_retry_escape() {
    let r=request(local::Phase::Prepare);let mut value=terminal(&r);
    value["status"]=json!("refused");value["reason"]=json!("branch-exists");
    value["firstFailureNs"]=json!(99_000_000_000u64);value["cleanupEndNs"]=json!(109_000_000_000u64);
    assert!(r.terminal(&raw(value.clone()),None).is_ok());
    let old_action:local::Action=serde_json::from_value(json!({"kind":"stage","expectedRevision":"a".repeat(64),
        "paths":["a.txt"],"message":null,"identity":null})).unwrap();
    let old=local::Request::from_original(&r.id,&old_action,&r.context,&native(),r.clock,None).unwrap();
    let mut bad=value.clone();bad["digest"]=json!(old.digest);bad["action"]=json!("stage");
    assert!(old.terminal(&raw(bad),None).is_err());
    value["status"]=json!("cleanup-unknown");value["reason"]=json!("unknown");
    assert!(!r.terminal(&raw(value),None).unwrap().child_declared_settled());
}
