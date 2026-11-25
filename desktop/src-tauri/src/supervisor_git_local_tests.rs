//! In-memory framing and original clock DATA. No native/provider/Store/file
//! call, real child, original NativeUse or positive native completion fixture.
use super::*;
use serde_json::json;
fn request(phase:wire::Phase)->Arc<wire::Request> {
    let action:wire::Action=serde_json::from_value(json!({"kind":"stage","expectedRevision":"a".repeat(64),
        "paths":["a.txt"],"message":null,"identity":null})).unwrap();
    let file=|uid,mode|wire::Snapshot {identity:(1,2,mode,uid,1001,1,12,123,456),sha256:"2".repeat(64)};
    let native=wire::Native {uid:1001,gid:1001,root:"/never-opened-git-frame".into(),
        directories:wire::Directories {root:(1,2,0o40700,1001,1001),git:(1,3,0o40700,1001,1001),objects:(1,4,0o40700,1001,1001)},
        tool:file(0,0o100755),files:wire::Files {head:file(1001,0o100600),config:file(1001,0o100600),index:Some(file(1001,0o100600))}};
    let review=wire::Review::Files(wire::FileReview {action:wire::Kind::Stage,expected_revision:"a".repeat(64),paths:vec!["a.txt".into()],whole_index:false,
        head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)});
    Arc::new(wire::Request::from_original("git-local-frame",&action,&wire::Context {project_id:"project-1".into(),generation:1,revision:"document-2".into()},
        &native,wire::Clock {work_end_ns:100_000_000_000,hard_end_ns:110_000_000_000},
        (phase==wire::Phase::Apply).then_some(wire::ApplyBinding {review,journal_revision:4})).unwrap())
}
fn raw(v:Value)->Vec<u8> {let mut v=serde_json::to_vec(&v).unwrap();v.push(b'\n');v}
fn ready(r:&wire::Request)->Vec<u8> {raw(json!({"protocol":wire::PROTOCOL,"id":r.id,"digest":r.digest}))}
fn candidate(r:&wire::Request)->Vec<u8> {raw(json!({"protocol":wire::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
    "reviewDigest":"b".repeat(64),"intent":{"action":"stage","expectedRevision":"a".repeat(64),"expectedRef":"refs/heads/main",
        "expectedHead":"1".repeat(40),"expectedIndex":"2".repeat(64),"candidateIndex":"3".repeat(64),"candidateCommit":null}}))}
fn refused(r:&wire::Request)->Vec<u8> {raw(json!({"protocol":wire::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,
    "phase":r.phase,"action":"stage","status":"refused","reason":"authorization","result":null,"publication":"not-reported",
    "firstFailureNs":99_000_000_000u64,"cleanupEndNs":109_000_000_000u64}))}
fn parse(bytes:&[u8],r:Arc<wire::Request>)->(ReadEnd,Result<(),BridgeError>,Option<Arc<wire::Candidate>>) {
    let runtime=tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        let (ready,returned)=oneshot::channel();let (candidate,observed)=oneshot::channel();let (faults,_)=mpsc::channel(4);
        let result=super::read(bytes,r,ready,candidate,faults,
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            None
        ).await;
        (result,returned.await.unwrap(),observed.await.ok())
    })
}
#[test]
fn local_pipe_candidate_is_private_once_and_terminal_is_separate_data() {
    let r=request(wire::Phase::Apply);let c=candidate(&r);let fin=refused(&r);
    let (out,ready,candidate)=parse(&[ready(&r),c,fin.clone()].concat(),r.clone());
    assert!(ready.is_ok()&&out.eof&&!out.overflow&&out.bytes==fin);
    let candidate=candidate.unwrap();assert!(r.ack(&candidate,5).is_ok());
    assert!(r.terminal(&out.bytes,Some(&candidate)).unwrap().child_declared_settled());
    // No SourceBook, original ACK job, NativeUse or native receipt exists here.
    assert!(!LocalResources::new(wire::Phase::Apply).complete());
}
#[test]
fn local_pipe_known_early_terminal_closes_candidate_without_grant() {
    for phase in [wire::Phase::Prepare,wire::Phase::Apply] {
        let r=request(phase);let fin=refused(&r);
        let (out,ready,candidate)=parse(&[ready(&r),fin.clone()].concat(),r.clone());
        assert!(ready.is_ok()&&out.eof&&!out.overflow&&out.bytes==fin&&candidate.is_none());
        assert!(r.terminal(&out.bytes,None).is_ok());
    }
}
#[test]
fn local_pipe_duplicate_candidate_never_becomes_terminal() {
    let r=request(wire::Phase::Apply);let c=candidate(&r);
    let (out,ready,candidate)=parse(&[ready(&r),c.clone(),c,refused(&r)].concat(),r.clone());
    assert!(ready.is_ok()&&candidate.is_some());
    assert!(r.terminal(&out.bytes,candidate.as_deref()).is_err());
}
#[test]
fn local_pipe_wrong_ready_prepare_candidate_and_missing_eof_data_refuse() {
    let r=request(wire::Phase::Prepare);
    let (out,parsed,_) =parse(&[raw(json!({"protocol":wire::PROTOCOL,"id":"foreign","digest":r.digest})),refused(&r)].concat(),r.clone());
    assert!(parsed.is_err()&&out.overflow);
    let (out,parsed,c)=parse(&[ready(&r),candidate(&r),refused(&r)].concat(),r.clone());
    assert!(parsed.is_ok()&&out.overflow&&c.is_none());
    let (out,parsed,c)=parse(b"",r.clone());
    assert!(parsed.is_err()&&c.is_none()&&r.terminal(&out.bytes,None).is_err());
}
#[test]
fn local_pipe_limit_and_extra_terminal_keep_bounded_refusal() {
    let r=request(wire::Phase::Prepare);
    let (out,_,_)=parse(&vec![b'x';wire::RESPONSE_LIMIT+4096],r.clone());
    assert!(out.eof&&out.overflow&&out.bytes.len()<=wire::RESPONSE_LIMIT);
    let fin=refused(&r);let (out,_,_)=parse(&[ready(&r),fin.clone(),fin].concat(),r.clone());
    assert!(r.terminal(&out.bytes,None).is_err());
}
#[test]
fn local_clock_is_one_original_45_55_with_earliest_failure() {
    let at=Instant::now();let end=Endpoints::at(at).unwrap();
    assert_eq!(end.work,at+Duration::from_secs(45));assert_eq!(end.hard,at+Duration::from_secs(55));
    let mut state=OwnerState::new(end.work,None);state.git_local_endpoints=Some(end);
    state.fail_at(BridgeError::timeout(),at+Duration::from_secs(4));
    state.fail_at(BridgeError::shutdown(),at+Duration::from_secs(1));
    state.fail_at(BridgeError::timeout(),at+Duration::from_secs(30));
    assert_eq!(state.endpoint,end.work);assert_eq!(state.cleanup_endpoint,Some(at+Duration::from_secs(11)));
    assert_eq!(end.first_failure(at+Duration::from_secs(100)),end.hard);
}
#[test]
fn local_child_data_and_empty_jobs_never_discharge_native_retirement() {
    let at=Instant::now();let mut state=OwnerState::new(at+Duration::from_secs(45),None);
    state.driver_end=Some(DriverEnd::Ready(Ok(ReadOutcome::GitLocal)));
    assert!(!state.management_ready()&&state.retirement_result(at,false).is_none());
    for phase in [wire::Phase::Prepare,wire::Phase::Apply] {
        let resources=LocalResources::new(phase);assert!(!resources.complete());
        assert!(!resources.candidate_pending());
    }
}
#[test]
fn local_known_post_go_stop_needs_private_closed_control_and_cancelled_terminal() {
    let r=request(wire::Phase::Apply);
    let mut row:Value=serde_json::from_slice(&refused(&r)).unwrap();row["status"]=json!("cancelled");
    let terminal=r.terminal(&raw(row.clone()),None).unwrap();
    let stopped=WriteEnd {complete:false};let waited=WriteEnd {complete:true};
    assert!(control_terminal_matches(Some(ControlClosed::StoppedAfterGo),Some(&stopped),true,&terminal));
    // Partial/ambiguous request, GO, ACK, close or writer join cannot provide
    // this original private value. False-complete or terminal DATA alone fails.
    for closed in [None,Some(ControlClosed::Waited)] {
        assert!(!control_terminal_matches(closed,Some(&stopped),true,&terminal));
    }
    assert!(!control_terminal_matches(Some(ControlClosed::StoppedAfterGo),None,true,&terminal));
    assert!(!control_terminal_matches(Some(ControlClosed::StoppedAfterGo),Some(&waited),true,&terminal));
    assert!(!control_terminal_matches(Some(ControlClosed::StoppedAfterGo),Some(&stopped),false,&terminal));
    assert!(control_terminal_matches(Some(ControlClosed::Waited),Some(&waited),false,&terminal));
    row["status"]=json!("timed-out");row["reason"]=json!("deadline");
    assert!(control_terminal_matches(Some(ControlClosed::StoppedAfterGo),Some(&stopped),true,&r.terminal(&raw(row),None).unwrap()));
    let mut success=terminal;success.status=crate::git_read_protocol::Outcome::Ok;
    assert!(!control_terminal_matches(Some(ControlClosed::StoppedAfterGo),Some(&stopped),true,&success));
    // Only DATA matching was exercised, not process/source/native settlement.
}
