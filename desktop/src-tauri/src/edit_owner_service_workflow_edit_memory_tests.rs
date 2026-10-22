//! Same original borrowed census. No byte-count stand-in or synthetic native join.
use super::*;
use sha2::Digest;
fn projection() -> EditProjection {
    EditProjection {
        domain:EditDomain::GitHubWorkflows,project_id:"workflow-project".into(),session_id:"1".repeat(32),owner_generation:"2".repeat(32),
        phase:Phase::Reviewing,review_remaining_ms:0,checkout:None,prepared:None,recovery:None,
        workflow:Some(w::Details::default()),metadata_text:None,release_version:None,metadata_images:None,identity:None,initialization:None,
        apply_submitted:false,core_outcome:None,native_reason:Reason::None,native_finality:NativeFinality::Pending,late_settled:false,
    }
}
fn maximum_frame() -> ChildFrame {
    let generated="y".repeat(16*1024);let previous="x".repeat(16*1024);
    let current_hash=format!("{:x}",sha2::Sha256::digest(generated.as_bytes()));
    let old_hash=format!("{:x}",sha2::Sha256::digest(previous.as_bytes()));
    let files:Vec<_>=w::IDS.into_iter().map(|id|json!({"id":id,"path":id.path(),"action":"update",
        "observed":{"state":"present","byteLength":previous.len(),"sha256":old_hash},
        "generated":{"byteLength":generated.len(),"sha256":current_hash,"content":generated},
        "previous":{"byteLength":previous.len(),"sha256":old_hash,"content":previous}})).collect();
    let mut bytes=serde_json::to_vec(&json!({"protocol":w::PROTOCOL,"session":"1".repeat(32),"seq":1,"kind":"prepared",
        "result":{"revision":"3".repeat(32),"planToken":"4".repeat(32),"scopeResources":"settled",
            "view":{"schemaVersion":1,"files":files,"createDirectories":[],
                "templateSet":{"coreVersion":"0.3.0","resourceVersion":1,"resourceSha256":"a".repeat(64)},
                "tooling":{"repository":"example/toolkit","sha":"b".repeat(40),"state":"format-only",
                    "schemaReference":format!("https://raw.githubusercontent.com/example/toolkit/{}/schemas/project.schema.json","b".repeat(40))}}}})).unwrap();
    bytes.push(b'\n');w::decode(&bytes,&"1".repeat(32)).unwrap()
}
fn prepared() -> EditProjection {
    let mut p=projection();let ChildFrame::WorkflowPrepared(reply)=maximum_frame() else {panic!("wrong original decoder arm")};
    let d=p.workflow.as_mut().unwrap();
    d.checkout=Some(w::Checkout{revision:reply.revision.clone(),observed:reply.view.files.iter().map(|f|match &f.observed {
        w::Observation::Present{byte_length,sha256}=>w::ObservedFile::Present{id:f.id,byte_length:*byte_length,sha256:sha256.clone()},
        w::Observation::Absent{}=>w::ObservedFile::Absent{id:f.id},
    }).collect()});
    d.prepared=Some(w::Prepared{revision:reply.revision,plan_token:reply.plan_token,draft_revision:7,baseline_generation:3,view:reply.view});p
}

#[test]
fn workflow_maximum_before_after_inventory_and_all_overlapping_frames_are_counted() {
    assert!(DECODE>=crate::protocol::NODE_LIMIT*512+7*w::RESPONSE_LIMIT);
    assert!(DECODE>=2*(8000*512+2*w::RESPONSE_LIMIT)+8000*128+1024);
    assert_eq!(FUTURE,INPUT+RUN+CONTROL+2*c::REQUEST_LIMIT);
    assert!(RUN>=3*REPRESENTATION+DECODE+6*ACTIVE_STATUS_WIRE);
    let p=projection();let frame=maximum_frame();prospective(&p,&frame).unwrap();
    let p=prepared();let actual=super::projection(&p).unwrap();
    assert!(actual<REPRESENTATION);prospective(&p,&ChildFrame::WorkflowTerminal(2,w::TerminalReply::Outcome{
        plan_token:Some("4".repeat(32)),effect:Effect::Committed,journal:Journal::Clean,resources:ResourceState::Settled,reason:CoreReason::None})).unwrap();
    eprintln!("Workflow representation={REPRESENTATION} decodedMax={actual} input={INPUT} run={RUN} decode={DECODE} future={FUTURE}");
}
#[test]
fn workflow_keeps_actual_old_inventory_and_refuses_overbound_without_clearing_it() {
    let owner=EditOwner::new(RuntimeConfig::packaged(PathBuf::from("/never-opened-workflow-census")));
    let empty=owner.workflow_edit_agent_edit_backing().unwrap();let old=prepared();
    let actual=super::projection(&old).unwrap();let wire=last_status_wire(&old).unwrap();
    owner.inner.lock().last=Some(old);
    assert!(owner.workflow_edit_agent_edit_backing().unwrap()>=empty+3*actual+6*wire);
    let mut r=owner.inner.lock();let p=r.last.as_mut().unwrap();
    // Genuine extra retained capacity, independent of the target's inline layout.
    p.project_id=String::with_capacity(64*1024*1024);p.project_id.push_str("workflow-project");
    let pointer=p.project_id.as_ptr();let capacity=p.project_id.capacity();drop(r);
    assert!(owner.workflow_edit_agent_edit_backing().is_err());
    let r=owner.inner.lock();assert_eq!(r.last.as_ref().unwrap().project_id.as_ptr(),pointer);assert_eq!(r.last.as_ref().unwrap().project_id.capacity(),capacity);
}
