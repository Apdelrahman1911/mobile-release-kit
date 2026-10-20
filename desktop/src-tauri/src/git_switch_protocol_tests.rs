//! Closed DATA tests through the real GitLocal codec. No native source, FD,
//! process, Store/ACK, current Doc or publication/finality is fabricated.
use super::*;
use serde_json::{json,Value};

pub(crate) fn selected()->Action {Action {kind:Kind::Switch,name:"next".into(),
    expected_revision:"a".repeat(64),expected_reference_revision:"c".repeat(64)}}
pub(crate) fn review()->Review {
    Review {action:Kind::Switch,name:"next".into(),target_ref:"refs/heads/next".into(),target_oid:"4".repeat(40),
        expected_revision:"a".repeat(64),expected_reference_revision:"c".repeat(64),head:"1".repeat(40),branch:"refs/heads/main".into(),
        expected_index:"2".repeat(64),paths:vec!["a.txt".into()],tracked_count:1,content_only:true,
        files:vec![File {path:"a.txt".into(),mode:"100644".into(),source_oid:"5".repeat(40),target_oid:"6".repeat(40),
            source_sha256:"7".repeat(64),target_sha256:"8".repeat(64),target_size:4}],
        log:Log {enabled:true,original_kind:"file".into(),original_sha256:"9".repeat(64)},review_digest:"b".repeat(64)}
}
pub(crate) fn intent()->Intent {
    let r=review();Intent {action:Kind::Switch,expected_revision:r.expected_revision,expected_reference_revision:r.expected_reference_revision,
        expected_ref:r.branch.clone(),expected_head:r.head,expected_index:r.expected_index,target_ref:r.target_ref.clone(),target_oid:r.target_oid,
        candidate_index:"d".repeat(64),original_head:hash(format!("ref: {}\n",r.branch).as_bytes()),
        candidate_head:hash(format!("ref: {}\n",r.target_ref).as_bytes()),original_log:r.log.original_sha256,
        candidate_log:"e".repeat(64),log_enabled:true,footprint:"f".repeat(64)}
}
pub(crate) fn native()->read::Native {
    let file=|ino,mode,sha|read::Snapshot {identity:(1,ino,mode,1001,1001,1,12,123,456),sha256:sha};
    read::Native {uid:1001,gid:1001,root:"/inert/project".into(),
        directories:read::Directories {root:(1,2,0o40700,1001,1001),git:(1,3,0o40700,1001,1001),objects:(1,4,0o40700,1001,1001)},
        tool:read::Snapshot {identity:(1,5,0o100755,0,0,1,12,123,456),sha256:"2".repeat(64)},
        files:read::Files {head:file(6,0o100644,intent().original_head),config:file(7,0o100600,"2".repeat(64)),
            index:Some(file(8,0o100644,"2".repeat(64)))}}
}
pub(crate) fn sources()->Sources {
    Sources {target_lock:TargetLock {identity:(1,9,0o100600,1001,1001,1,0,123,456),
        parent_before:(1,10,0o40700,1001,1001,2,4096,111,222),parent_locked:(1,10,0o40700,1001,1001,2,4096,333,444)},
        head_log:Some(read::Snapshot {identity:(1,11,0o100644,1001,1001,1,12,123,456),sha256:"9".repeat(64)}),
        files:vec![NamedSnapshot {path:"a.txt".into(),snapshot:read::Snapshot {identity:(1,12,0o100644,1001,1001,1,12,123,456),sha256:"7".repeat(64)}}]}
}
pub(crate) fn request(phase:local::Phase)->local::Request {
    local::Request::from_switch_original("switch-fixture",&local::Action::Switch(selected()),
        &read::Context {project_id:"runtime-alias".into(),generation:1,revision:"document-2".into()},&native(),
        read::Clock {work_end_ns:100_000_000_000,hard_end_ns:110_000_000_000},
        (phase==local::Phase::Apply).then(||local::ApplyBinding {review:local::Review::Switch(review()),journal_revision:4}),
        (phase==local::Phase::Apply).then(sources)).unwrap()
}
pub(crate) fn raw(value:Value)->Vec<u8> {let mut v=serde_json::to_vec(&value).unwrap();v.push(b'\n');v}
pub(crate) fn candidate(r:&local::Request)->local::Candidate {r.candidate(&raw(candidate_value(r))).unwrap()}
fn candidate_value(r:&local::Request)->Value {json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
    "reviewDigest":review().review_digest,"intent":intent()})}
fn terminal(r:&local::Request)->Value {json!({"protocol":local::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,
    "phase":r.phase,"action":"branch-switch","status":"ok","reason":null,"result":null,"publication":"not-reported",
    "firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns})}
fn applied(r:&local::Request)->Value {let mut v=terminal(r);v["publication"]=json!("switch-index-returned");
    v["result"]=json!({"operationId":r.id,"action":"branch-switch","state":"succeeded","settlement":"settled","reason":null,
        "observation":{"revision":"e".repeat(64),"head":review().target_oid,"branch":review().target_ref,"unborn":false,"detached":false,
            "changes":[],"remotes":[],"restrictions":[]},"intent":intent(),"effectPhase":"index-returned","retainedPaths":[]});v}

#[test]
fn switch_command_requires_exact_name_and_both_current_revisions_without_caller_controls() {
    let value=json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":selected()});
    let local::Command::Prepare(p)=local::decode_command("git_local_prepare",&raw(value.clone())).unwrap() else {panic!()};
    assert!(p.action.kind()==local::Kind::BranchSwitch && p.action.valid());
    assert_eq!(serde_json::to_value(p.action.public()).unwrap(),json!(selected()));
    for field in ["paths","force","discardChanges","autostash","identity","message","targetOid","switch","argv","root"] {
        let mut bad=value.clone();bad["action"][field]=Value::Null;
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    for field in ["expectedRevision","expectedReferenceRevision","name"] {
        let mut bad=value.clone();bad["action"].as_object_mut().unwrap().remove(field);
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    for name in ["-f","@{-1}","a..b","a.lock","a/.b","a//b","", "é"] {
        let mut bad=value.clone();bad["action"]["name"]=json!(name);
        assert!(local::decode_command("git_local_prepare",&raw(bad)).is_err());
    }
    assert!(local::decode_command("git_local_prepare",b"{\"action\":null,\"action\":null}").is_err());
}

#[test]
fn switch_review_is_exact_bounded_content_only_and_same_tree_is_not_a_fake_noop() {
    let r=request(local::Phase::Prepare);let mut value=terminal(&r);value["result"]=json!({"review":review()});
    assert!(r.terminal(&raw(value.clone()),None).unwrap().review().unwrap()==local::Review::Switch(review()));
    for (field,v) in [("contentOnly",json!(false)),("targetRef",json!("refs/heads/main")),("targetOid",json!("x")),
        ("expectedReferenceRevision",json!("0".repeat(64))),("trackedCount",json!(257)),("paths",json!([]))] {
        let mut bad=value.clone();bad["result"]["review"][field]=v;
        assert!(r.terminal(&raw(bad),None).is_err());
    }
    let mut same=review();same.target_oid=same.head.clone();same.files.clear();same.paths.clear();
    assert!(same.valid());value["result"]=json!({"review":same});assert!(r.terminal(&raw(value.clone()),None).is_ok());
    value["result"]["diff"]=Value::Null;assert!(r.terminal(&raw(value),None).is_err());
    let mut oversized=review();oversized.files[0].target_size=FILE_LIMIT+1;assert!(!oversized.valid());
    let mut duplicate=review();duplicate.files.push(duplicate.files[0].clone());duplicate.paths.push("a.txt".into());assert!(!duplicate.valid());
}

#[test]
fn private_switch_request_needs_same_native_sources_but_no_new_public_grant() {
    let r=request(local::Phase::Apply);let v:Value=serde_json::from_slice(r.bytes()).unwrap();
    assert_eq!(v["switch"],json!(sources()));assert_eq!(v["context"]["revision"],"document-2");
    let prepare=request(local::Phase::Prepare);let p:Value=serde_json::from_slice(prepare.bytes()).unwrap();assert!(p["switch"].is_null());
    assert!(local::Request::from_original(&r.id,&r.action,&r.context,r.native.as_ref().unwrap(),r.clock,
        Some(local::ApplyBinding {review:local::Review::Switch(review()),journal_revision:4})).is_err());
    let mut bad=sources();bad.target_lock.parent_locked.1+=1;assert!(!bad.valid(&native(),&review()));
    bad=sources();bad.target_lock.identity.6=1;assert!(!bad.valid(&native(),&review()));
    bad=sources();bad.files[0].snapshot.sha256="f".repeat(64);assert!(!bad.valid(&native(),&review()));
    bad=sources();bad.head_log=None;assert!(!bad.valid(&native(),&review()));
    let mut absent=review();absent.log=Log {enabled:false,original_kind:"absent".into(),original_sha256:hash(b"absent")};
    bad=sources();bad.head_log=None;assert!(bad.valid(&native(),&absent));
    let mut changed=native();changed.files.head.sha256=hash(b"ref: refs/heads/other\n");assert!(!bad.valid(&changed,&absent));
}

#[test]
fn switch_candidate_binds_originals_exact_target_metadata_and_one_original_ack_revision() {
    let r=request(local::Phase::Apply);let c=candidate(&r);r.ack(&c,5).unwrap();
    assert!(r.ack(&c,4).is_err()&&r.ack(&c,6).is_err());
    for (field,v) in [("expectedRevision",json!("f".repeat(64))),("expectedReferenceRevision",json!("f".repeat(64))),
        ("expectedRef",json!("refs/heads/other")),("expectedHead",json!("7".repeat(40))),("expectedIndex",json!("f".repeat(64))),
        ("targetRef",json!("refs/heads/other")),("targetOid",json!("7".repeat(40))),("originalHead",json!("f".repeat(64))),
        ("candidateHead",json!("f".repeat(64))),("originalLog",json!("f".repeat(64))),("logEnabled",json!(false)),
        ("footprint",json!("bad")),("candidateCommit",Value::Null)] {
        let mut bad=candidate_value(&r);bad["intent"][field]=v;assert!(r.candidate(&raw(bad)).is_err());
    }
    assert!(request(local::Phase::Prepare).candidate(&raw(candidate_value(&r))).is_err());
}

#[test]
fn switch_success_needs_exact_index_publication_target_and_no_failure_or_retained_candidates() {
    let r=request(local::Phase::Apply);let c=candidate(&r);let good=applied(&r);
    assert!(r.terminal(&raw(good.clone()),Some(&c)).unwrap().child_declared_settled());
    assert!(r.terminal(&raw(good.clone()),None).is_err());
    for (marker,phase) in [("not-reported","not-published"),("switch-checkout-returned","worktree-returned"),
        ("switch-log-returned","head-log-returned"),("switch-head-returned","head-returned"),("index-returned","index-returned")] {
        let mut bad=good.clone();bad["publication"]=json!(marker);bad["result"]["effectPhase"]=json!(phase);
        assert!(r.terminal(&raw(bad),Some(&c)).is_err());
    }
    for (field,v) in [("head",json!(review().head)),("branch",json!(review().branch))] {
        let mut bad=good.clone();bad["result"]["observation"][field]=v;assert!(r.terminal(&raw(bad),Some(&c)).is_err());
    }
    let mut bad=good;bad["result"]["retainedPaths"]=json!([".git/mrk-git-fixture/index"]);
    assert!(r.terminal(&raw(bad),Some(&c)).is_err());
}

#[test]
fn known_partial_switch_is_recovery_only_and_keeps_fixed_recoverable_relative_candidates() {
    let r=request(local::Phase::Apply);let c=candidate(&r);
    for (marker,phase) in [("not-reported","not-published"),("switch-checkout-returned","worktree-returned"),
        ("switch-log-returned","head-log-returned"),("switch-head-returned","head-returned"),("switch-index-returned","index-returned")] {
        let mut v=applied(&r);v["publication"]=json!(marker);v["firstFailureNs"]=json!(99_000_000_000u64);v["cleanupEndNs"]=json!(109_000_000_000u64);
        v["result"]["state"]=json!("recovery-required");v["result"]["reason"]=json!("recovery-required");
        v["result"]["observation"]=Value::Null;v["result"]["effectPhase"]=json!(phase);
        v["result"]["retainedPaths"]=json!([".git/mrk-git-fixture/HEAD",".git/mrk-git-fixture/index"]);
        assert!(r.terminal(&raw(v.clone()),Some(&c)).is_ok());
        v["result"]["state"]=json!("failed");assert!(r.terminal(&raw(v.clone()),Some(&c)).is_err());
        v["result"]["state"]=json!("recovery-required");
        for paths in [json!(["/private/file"]),json!([".git/mrk-git-fixture/../../config"]),json!([".git/mrk-git-fixture/token"]),
            json!([".git/mrk-git-fixture/index",".git/mrk-git-fixture/HEAD"])] {
            v["result"]["retainedPaths"]=paths;assert!(r.terminal(&raw(v.clone()),Some(&c)).is_err());
        }
    }
}

#[test]
fn switch_unknown_missing_fields_and_refusal_are_not_old_action_retry_or_success() {
    let r=request(local::Phase::Prepare);let mut value=terminal(&r);
    value["status"]=json!("refused");value["reason"]=json!("switch-layout");
    value["firstFailureNs"]=json!(99_000_000_000u64);value["cleanupEndNs"]=json!(109_000_000_000u64);
    assert!(r.terminal(&raw(value.clone()),None).is_ok());
    value["status"]=json!("cleanup-unknown");value["reason"]=json!("unknown");
    assert!(!r.terminal(&raw(value),None).unwrap().child_declared_settled());
    let r=request(local::Phase::Apply);let c=candidate(&r);let value=applied(&r);
    for key in ["effectPhase","retainedPaths","intent"] {
        let mut bad=value.clone();bad["result"].as_object_mut().unwrap().remove(key);assert!(r.terminal(&raw(bad),Some(&c)).is_err());
    }
    let mut bad=value;bad["result"]["force"]=json!(false);assert!(r.terminal(&raw(bad),Some(&c)).is_err());
}

#[test]
fn replacement_group_and_lock_parent_comparisons_do_not_allow_group_repairs_or_namespace_replacement() {
    let f=sources().files[0].snapshot.identity;let parent=native().directories.root;
    assert!(replacement_group(f,parent));let mut overridden=f;overridden.4+=1;assert!(!replacement_group(overridden,parent));
    let old=sources().target_lock.parent_before;let next=sources().target_lock.parent_locked;assert!(parent_transition(old,next));
    for changed in [(2,old.1,old.2,old.3,old.4,old.5,old.6,old.7,old.8),
        (old.0,old.1,old.2,old.3,old.4+1,old.5,old.6,old.7,old.8),
        (old.0,old.1,old.2,old.3,old.4,old.5+1,old.6,old.7,old.8)] {assert!(!parent_transition(old,changed));}
}

#[test]
fn final_recovery_data_requires_same_validated_original_positive_phase_and_cannot_create_finality() {
    let r=request(local::Phase::Apply);let c=candidate(&r);
    let t=r.terminal(&raw(applied(&r)),Some(&c)).unwrap();
    let d=FinalData::from_returned(&r,&c,&t,local::Publication::SwitchIndexReturned).unwrap();assert!(d.successful());
    assert!(FinalData::from_returned(&r,&c,&t,local::Publication::NotReported).is_err());
    assert!(FinalData::from_returned(&r,&c,&t,local::Publication::SwitchHeadReturned).is_err());
    let mut foreign=request(local::Phase::Apply);foreign.id="other-original".into();
    assert!(FinalData::from_returned(&foreign,&c,&t,local::Publication::SwitchIndexReturned).is_err());
    let mut invalid=d;invalid.effect_phase="not-published".into();assert!(!invalid.valid());
    // The DATA output is not a NativeJoined witness and cannot call the Store.
}
