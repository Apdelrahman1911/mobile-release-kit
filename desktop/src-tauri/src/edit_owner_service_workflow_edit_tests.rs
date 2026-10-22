//! Actual protocol-decoded inert maximum inventory, never a native Session or filesystem receipt.
use super::*;
use crate::github_workflow_edit_protocol as w;
use crate::edit_protocol::CoreEditOutcome;
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
    let files:Vec<_>=[w::WorkflowId::Preflight,w::WorkflowId::Candidate,w::WorkflowId::ExternalTesting,w::WorkflowId::ProductionSubmit].into_iter().map(|id|json!({"id":id,"path":id.path(),"action":"update",
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
fn workflow_seven_original_publications_do_not_skip_repeat_or_rebase() {
    let mut stage=Stage::Bound;
    for step in [Step::Open,Step::Opened,Step::Prepare,Step::Prepared,Step::Apply,Step::Terminal,Step::Retired] {
        let next=successor(stage,step).unwrap();assert!(successor(next,step).is_none());stage=next;
    }
    assert_eq!(stage,Stage::Returned);
    assert!(successor(Stage::Opening,Step::Apply).is_none());
    assert!(successor(Stage::Reviewing,Step::Terminal).is_none());
    assert!(successor(Stage::Finalizing,Step::Prepare).is_none());
}
#[test]
fn exact_four_file_summary_comes_from_original_full_preview_never_recovery_or_public_ids() {
    assert!(review(&projection(),12).is_err());
    let mut p=prepared();let r=review(&p,12).unwrap();
    assert_eq!((r.draft_revision,r.baseline_generation),(7,3));
    assert_eq!(r.files.len(),4);assert_eq!(r.tooling_repository,"example/toolkit");
    for file in &r.files {assert_eq!(file.action,p::FileAction::Update);assert_eq!(file.generated.byte_length,16384);assert_eq!(file.observed.as_ref().unwrap().byte_length,16384);}
    assert_eq!(r.plan_token.as_str(),"4".repeat(32));assert_eq!(r.native_status_revision,12);
    let serialized=serde_json::to_value(&r).unwrap();
    assert!(serialized["files"].as_array().unwrap().iter().all(|f|f.get("content").is_none() && f["generated"].get("content").is_none()));
    p.workflow.as_mut().unwrap().recovery=Some(w::RecoveryDetails::default());
    assert!(review(&p,12).is_err());
}
#[test]
fn workflow_positive_attribution_needs_original_chain_and_real_finality_preserving_core_first_reason() {
    let mut p=prepared();p.apply_submitted=true;
    p.core_outcome=Some(CoreEditOutcome{effect:Effect::Committed,journal:Journal::Clean,resources:ResourceState::Settled,reason:CoreReason::None});
    assert!(final_data(&p,false).is_none());
    let mut unknown=false;fence_retirement(&mut p,&mut unknown,false);
    assert!(unknown);assert_eq!(p.native_reason,Reason::CallerLost);assert_eq!(p.native_finality,NativeFinality::Pending);
    assert_eq!(p.core_outcome.as_ref().unwrap().effect,Effect::Committed);
    p.native_reason=Reason::Cancelled;fence_retirement(&mut p,&mut unknown,false);assert_eq!(p.native_reason,Reason::Cancelled);
    let mut failed=prepared();failed.core_outcome=Some(CoreEditOutcome{effect:Effect::NotStarted,journal:Journal::NotCreated,resources:ResourceState::Settled,reason:CoreReason::Cancelled});
    let mut unknown=false;fence_retirement(&mut failed,&mut unknown,false);assert!(!unknown);assert!(final_data(&failed,false).is_none());
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn workflow_edit_code_census_borrows_only_the_same_live_slot_and_refuses_busy_or_lost() {
    let original = Arc::new(Mutex::new(InstalledEditSlots::GitHubWorkflows(
        GitHubWorkflowRuntimeSlots::new(),
    )));
    let weak = Arc::downgrade(&original);
    assert!(native_code_bytes(&weak).is_err()); // Ordinary slot is not opted in.
    {
        let mut held = original.lock().unwrap();
        let InstalledEditSlots::GitHubWorkflows(slots) = &mut *held else {
            unreachable!()
        };
        slots.bind_workflow_edit_agent_inspection().unwrap();
        assert!(slots.never_started());
        assert!(native_code_bytes(&weak).is_err()); // No wait or zero fallback.
    }
    let count = native_code_bytes(&weak).unwrap();
    assert_eq!(
        count,
        std::mem::size_of::<GitHubWorkflowRuntimeSlots>()
    );
    assert_eq!(Arc::strong_count(&original), 1); // No additional retained owner.
    let poisoned = original.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = poisoned.lock().unwrap();
        panic!("inert original slot poison");
    }));
    drop(poisoned);
    assert!(native_code_bytes(&weak).is_err());
    drop(original);
    assert!(native_code_bytes(&weak).is_err());
    let foreign = Arc::new(Mutex::new(InstalledEditSlots::Configuration(
        ConfigurationRuntimeSlots::new(),
    )));
    assert!(native_code_bytes(&Arc::downgrade(&foreign)).is_err());
}
