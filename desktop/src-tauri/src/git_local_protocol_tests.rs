//! Synthetic DATA only. No process, file, NativeUse or native-source admission.
use super::*;

fn action(kind:Kind) -> Action {
    Action::Files(FileAction {kind,expected_revision:"a".repeat(64),paths:if kind==Kind::Commit {vec![]} else {vec!["a.txt".into()]},
        message:(kind==Kind::Commit).then(||"Reviewed complete staged changes".into()),
        identity:(kind==Kind::Commit).then(||Identity {name:"Fixture".into(),email:"fixture@example.invalid".into()})})
}
fn review(kind:Kind) -> Review {
    Review::Files(FileReview {action:kind,expected_revision:"a".repeat(64),paths:if kind==Kind::Commit {vec!["a.txt".into(),"b.txt".into()]} else {vec!["a.txt".into()]},
        whole_index:kind==Kind::Commit,head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),
        expected_index:"2".repeat(64),review_digest:"b".repeat(64)})
}
fn native() -> Native {
    let file=|uid,mode| Snapshot {identity:(1,2,mode,uid,1001,1,12,123,456),sha256:"2".repeat(64)};
    Native {uid:1001,gid:1001,root:"/fixture/project".into(),
        directories:Directories {root:(1,2,0o40700,1001,1001),git:(1,3,0o40700,1001,1001),objects:(1,4,0o40700,1001,1001)},
        tool:file(0,0o100755),files:Files {head:file(1001,0o100600),config:file(1001,0o100600),index:Some(file(1001,0o100600))}}
}
fn request(kind:Kind, phase:Phase) -> Request {
    Request::from_original("local-fixture",&action(kind),&Context {project_id:"runtime-alias".into(),generation:1,revision:"document-2".into()},
        &native(),Clock {work_end_ns:100_000_000_000,hard_end_ns:110_000_000_000},
        (phase==Phase::Apply).then(||ApplyBinding {review:review(kind),journal_revision:4})).unwrap()
}
fn raw(value:Value) -> Vec<u8> { let mut bytes=serde_json::to_vec(&value).unwrap();bytes.push(b'\n');bytes }
fn candidate(request:&Request) -> (Value,Candidate) {
    let review=request.binding.as_ref().unwrap().review.file().unwrap();
    let intent=Intent::Files(FileIntent {action:review.action,expected_revision:review.expected_revision.clone(),expected_ref:review.branch.clone(),
        expected_head:review.head.clone(),expected_index:review.expected_index.clone(),
        candidate_index:(review.action!=Kind::Commit).then(||"3".repeat(64)),
        candidate_commit:(review.action==Kind::Commit).then(||"4".repeat(40))});
    let value=json!({"protocol":PROTOCOL,"kind":"candidate","id":request.id,"digest":request.digest,
        "reviewDigest":review.review_digest,"intent":intent});
    let parsed=request.candidate(&raw(value.clone())).unwrap();(value,parsed)
}
fn terminal(request:&Request) -> Value {
    json!({"protocol":PROTOCOL,"kind":"terminal","id":request.id,"digest":request.digest,"phase":request.phase,
        "action":request.action.kind(),"status":"refused","reason":"unsupported-repository","result":null,
        "publication":"not-reported","firstFailureNs":99_000_000_000u64,"cleanupEndNs":109_000_000_000u64})
}

#[test]
fn strict_local_commands_have_no_provider_or_serialized_plan_route() {
    let good=json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":action(Kind::Commit)});
    let Command::Prepare(parsed)=decode_command("git_local_prepare",&raw(good.clone())).unwrap() else {panic!()};
    let public=serde_json::to_string(&parsed.action.public()).unwrap();
    assert!(!public.contains("Fixture") && !public.contains("Reviewed") && !public.contains("@"));
    for key in ["argv","environment","plan","executable","authority"] {
        let mut row=good.clone();row[key]=json!(true);assert!(decode_command("git_local_prepare",&raw(row)).is_err());
    }
    for kind in ["reset","fetch","push","branch","switch","add"] {
        let mut row=good.clone();row["action"]["kind"]=json!(kind);assert!(decode_command("git_local_prepare",&raw(row)).is_err());
    }
    assert!(decode_command("git_local_prepare",b"{\"projectId\":\"a\",\"projectId\":\"b\"}").is_err());
    assert!(decode_command("git_local_apply",&raw(json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"reviewId":"review-1","action":action(Kind::Stage)}))).is_err());
    assert!(matches!(decode_command("git_local_status",b"{}").unwrap(),Command::Status));
}

#[test]
fn private_request_requires_exact_retained_review_index_and_clock() {
    let r=request(Kind::Stage,Phase::Apply);let data:Value=serde_json::from_slice(r.bytes()).unwrap();
    assert!(data["protocol"]==PROTOCOL && data["journalRevision"]==4 && data["reviewDigest"]=="b".repeat(64));
    let mut changed=review(Kind::Stage);let Review::Files(file)=&mut changed else {panic!()};file.expected_index="f".repeat(64);
    assert!(Request::from_original(&r.id,&r.action,&r.context,&native(),r.clock,Some(ApplyBinding {review:changed,journal_revision:4})).is_err());
    assert!(Request::from_original(&r.id,&r.action,&r.context,&native(),Clock {hard_end_ns:r.clock.hard_end_ns+1,..r.clock},None).is_err());
    let mut changed=native();changed.uid=0;
    assert!(Request::from_original(&r.id,&r.action,&r.context,&changed,r.clock,None).is_err());
    for revision in [0,u64::MAX-1,u64::MAX] {
        assert!(Request::from_original(&r.id,&r.action,&r.context,&native(),r.clock,Some(ApplyBinding {review:review(Kind::Stage),journal_revision:revision})).is_err());
    }
}

#[test]
fn ready_go_and_candidate_ack_bind_original_request_and_revision() {
    let r=request(Kind::Stage,Phase::Apply);
    r.ready(&raw(json!({"protocol":PROTOCOL,"id":r.id,"digest":r.digest}))).unwrap();
    assert!(r.go()==format!("MRK-GIT-LOCAL-GO/1 {}\n",r.digest).into_bytes());
    let (_,c)=candidate(&r);
    assert!(r.ack(&c,5).unwrap()==format!("MRK-GIT-LOCAL-ACK/1 {} {} 5\n",r.digest,c.digest).into_bytes());
    assert!(r.ack(&c,4).is_err() && r.ack(&c,6).is_err());
    let other=request(Kind::Unstage,Phase::Apply);assert!(other.ack(&c,5).is_err());
}

#[test]
fn candidate_is_exclusive_and_cannot_change_head_index_or_ref() {
    for kind in [Kind::Stage,Kind::Unstage,Kind::Commit] {
        let r=request(kind,Phase::Apply);let (good,_)=candidate(&r);
        for (key,value) in [("expectedIndex",json!("f".repeat(64))),("expectedHead",json!("5".repeat(40))),
            ("expectedRef",json!("refs/heads/other")),("action",json!("reset"))] {
            let mut row=good.clone();row["intent"][key]=value;assert!(r.candidate(&raw(row)).is_err());
        }
        let mut row=good;row["intent"][if kind==Kind::Commit {"candidateIndex"} else {"candidateCommit"}]=json!("f".repeat(64));
        assert!(r.candidate(&raw(row)).is_err());
    }
    let a=request(Kind::Stage,Phase::Apply);let (row,_)=candidate(&a);
    assert!(request(Kind::Stage,Phase::Prepare).candidate(&raw(row)).is_err());
}

#[test]
fn prepare_terminal_names_all_staged_paths_without_private_draft() {
    let r=request(Kind::Commit,Phase::Prepare);let mut row=terminal(&r);
    row["status"]=json!("ok");row["reason"]=Value::Null;row["firstFailureNs"]=Value::Null;row["cleanupEndNs"]=json!(r.clock.hard_end_ns);
    row["result"]=json!({"review":review(Kind::Commit),"diff":{"revision":"a".repeat(64),"staged":true,"paths":["a.txt","b.txt"],"text":"inert diff","withheld":null}});
    let parsed=r.terminal(&raw(row.clone()),None).unwrap();assert!(parsed.review().unwrap().file().unwrap().paths.len()==2);
    assert!(!String::from_utf8(raw(row.clone())).unwrap().contains("fixture@example"));
    row["result"]["diff"]["paths"]=json!(["a.txt"]);assert!(r.terminal(&raw(row),None).is_err());
}

#[test]
fn applied_success_requires_candidate_and_positive_publication_not_finality() {
    let r=request(Kind::Commit,Phase::Apply);let (_,c)=candidate(&r);let mut row=terminal(&r);
    row["status"]=json!("ok");row["reason"]=Value::Null;row["firstFailureNs"]=Value::Null;row["cleanupEndNs"]=json!(r.clock.hard_end_ns);
    row["publication"]=json!("ref-returned");
    row["result"]=json!({"operationId":r.id,"action":"commit","state":"succeeded","settlement":"settled","reason":null,"intent":c.intent,
        "observation":{"revision":"e".repeat(64),"head":"4".repeat(40),"branch":"refs/heads/main","unborn":false,"detached":false,"changes":[],"remotes":[],"restrictions":[]}});
    let parsed=r.terminal(&raw(row.clone()),Some(&c)).unwrap();assert!(parsed.child_declared_settled());
    assert!(r.terminal(&raw(row.clone()),None).is_err());
    for p in ["not-reported","index-returned"] {let mut bad=row.clone();bad["publication"]=json!(p);assert!(r.terminal(&raw(bad),Some(&c)).is_err());}
    row["result"]["observation"]["head"]=json!("5".repeat(40));assert!(r.terminal(&raw(row),Some(&c)).is_err());
}

#[test]
fn core_recovery_is_not_success_or_permission_to_repeat_and_unknown_is_absorbing() {
    let r=request(Kind::Stage,Phase::Apply);let (_,c)=candidate(&r);let mut row=terminal(&r);
    row["status"]=json!("ok");row["reason"]=Value::Null;
    row["result"]=json!({"operationId":r.id,"action":"stage","state":"recovery-required","settlement":"settled",
        "reason":"authorization","observation":null,"intent":c.intent});
    assert!(r.terminal(&raw(row.clone()),Some(&c)).is_ok());
    row["firstFailureNs"]=Value::Null;assert!(r.terminal(&raw(row),Some(&c)).is_err());
    let mut unknown=terminal(&r);unknown["status"]=json!("cleanup-unknown");unknown["reason"]=json!("unknown");
    assert!(!r.terminal(&raw(unknown),Some(&c)).unwrap().child_declared_settled());
}

#[test]
fn malformed_duplicate_oversize_and_extended_failure_cutoff_never_settle() {
    let r=request(Kind::Stage,Phase::Prepare);let mut row=terminal(&r);
    assert!(r.terminal(&raw(row.clone()),None).is_ok());
    row["cleanupEndNs"]=json!(110_000_000_000u64);assert!(r.terminal(&raw(row),None).is_err());
    assert!(r.terminal(&vec![b'x';RESPONSE_LIMIT+1],None).is_err());
    let raw=raw(terminal(&r));let mut duplicate=raw.clone();duplicate.extend_from_slice(&raw);assert!(r.terminal(&duplicate,None).is_err());
}

#[test]
fn local_admission_keeps_document_writer_and_full_code_partitions_independent() {
    let mib=1024*1024;
    let code=crate::macos_history_inventory::CODE_CONTROL_RESERVE;
    assert_eq!(code,128*mib);
    for (document,future,expected) in [
        (0,code,Some(code)),
        (16*mib,code,Some(144*mib)),
        (0,code+16*mib,Some(144*mib)),
        (16*mib,code+16*mib,Some(160*mib)),
        (16*mib+1,code,None),
        (0,code+16*mib+1,None),
        (0,code-1,None),
        (16*mib,0,None),
        (usize::MAX,code,None),
        (1,usize::MAX,None),
        (0,usize::MAX,None),
    ] { assert_eq!(admission_bytes(document,future),expected); }
}
