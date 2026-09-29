// Pure codec and native-state predicate DATA. No native picker, vault load,
// child, crypto, runtime grant, registry IO or real cleanup receipt is created.
use super::*;
use serde_json::json;
#[test]
fn all_eleven_groups_use_original_field_names_and_exact_file_base64() {
    let bytes=[0u8,255,1,42];let sample="  fictional 🔐\n\"\\\0  ";
    for kind in [Kind::AndroidKeystore,Kind::AndroidFirebase,Kind::AppleP12,Kind::AppleProfile,Kind::AscP8,
        Kind::IosFirebase,Kind::GoogleWif,Kind::ProjectReadToken,Kind::AppleReviewContact,
        Kind::AppleReviewDemoAccount,Kind::AppleOperationCommitment] {
        let file=kind.file().map(|_| bytes.as_slice());let mut values=Map::new();
        if file.is_some() {values.insert("file".into(),json!("AP8BKg=="));}
        for name in commands::field_names(kind) {values.insert((*name).into(),json!(sample));}
        let mut count=Count(0);encode_parts(kind,file,|_|Some(sample),&mut count).unwrap();
        let mut writer=wire::PrivateWriter::new(wire::ENVELOPE_LIMIT).unwrap();
        encode_parts(kind,file,|_|Some(sample),&mut writer).unwrap();let envelope=writer.finish();
        assert_eq!(envelope.len(),count.0);assert!(envelope.capacity()<=wire::ENVELOPE_LIMIT);
        assert_eq!(crate::protocol::strict_json(&envelope).unwrap(),json!({"protocol":wire::ENVELOPE_PROTOCOL,"kind":kind.name(),"values":values}));
        if !commands::field_names(kind).is_empty() {assert!(encode_parts(kind,file,|_|None,&mut Count(0)).is_err());}
        assert!(encode_parts(kind,if file.is_some() {None} else {Some(&bytes)},|_|Some(sample),&mut Count(0)).is_err());
    }
}
#[test]
fn exact_serialized_bound_refuses_without_splitting_or_dropping_a_field() {
    let file=vec![0u8;35_000];let kind=Kind::AndroidKeystore;let mut baseline=Count(0);
    encode_parts(kind,Some(&file),|_|Some(""),&mut baseline).unwrap();
    let pad=wire::ENVELOPE_LIMIT-baseline.0;assert!(pad<4096);
    let mut password="x".repeat(pad);
    let mut count=Count(0);encode_parts(kind,Some(&file),|name|Some(if name=="storePassword" {&password} else {""}),&mut count).unwrap();
    assert_eq!(count.0,wire::ENVELOPE_LIMIT);
    let mut writer=wire::PrivateWriter::new(wire::ENVELOPE_LIMIT).unwrap();
    encode_parts(kind,Some(&file),|name|Some(if name=="storePassword" {&password} else {""}),&mut writer).unwrap();
    assert_eq!(writer.finish().len(),wire::ENVELOPE_LIMIT);
    password.push('x');
    assert!(encode_parts(kind,Some(&file),|name|Some(if name=="storePassword" {&password} else {""}),&mut Count(0)).is_err());
}
#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
fn data() -> (DocumentState,Arc<()>,Arc<GitHubInputMaterial>) {
    let mut state=crate::asset_session::tests::empty_state();
    state.lifetime.crash_hook_installed();state.lifetime.started(true);state.lifetime.finished(true);state.revision=1;
    let identity=Arc::new(());
    let native=Arc::new(NativeContext {revision:1,project_id:"data-project".into(),registry_generation:7,
        project:asset_source::RegisteredRoot {path:"/inert/project".into(),identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity())},
        draft:b"{}".to_vec(),platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Full});
    let payload=Arc::new(Payload {kind:Kind::ProjectReadToken,material:None,
        fields:Some(commands::own_fields(Kind::ProjectReadToken,&json!({"token":"fictional-not-a-credential"})).unwrap_or_else(|_| panic!("fixed synthetic token fields rejected")))});
    let holding=Arc::new(AssignedPayload {payload:payload.clone(),reference:None});
    let assignment=wire::AssignmentRef {kind:Kind::ProjectReadToken,record_id:"a".repeat(32),record_revision:1,context_revision:1};
    state.records.push(Record {key:RecordKey {id:Token(assignment.record_id.clone()),revision:1},payload,mutation_pending:false});
    state.assignments.push(Assignment {kind:assignment.kind,record_id:Token(assignment.record_id.clone()),record_revision:1,context_revision:1,
        availability:AssignmentAvailability::Available,holding:Some(holding.clone())});state.context=Some(native.clone());
    let material=Arc::new(GitHubInputMaterial {document:Arc::downgrade(&identity),native,holding,assignment,native_config_sha256:wire::digest(b"{}")});
    (state,identity,material)
}
#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn current_loan_requires_original_document_context_record_and_holding_identity() {
    let (mut state,identity,material)=data();let root=material.native.project.clone();
    assert!(material.current(&state,&identity,7,&root));
    assert!(!material.current(&state,&Arc::new(()),7,&root));assert!(!material.current(&state,&identity,8,&root));
    let old=state.assignments[0].holding.take();assert!(!material.current(&state,&identity,7,&root)); // Metadata is not a payload loan.
    state.assignments[0].holding=Some(Arc::new(AssignedPayload {payload:material.holding.payload.clone(),reference:None}));
    assert!(!material.current(&state,&identity,7,&root));state.assignments[0].holding=old;
    state.records[0].mutation_pending=true;assert!(!material.current(&state,&identity,7,&root));state.records[0].mutation_pending=false;
    state.records[0].key.revision=2;assert!(!material.current(&state,&identity,7,&root));state.records[0].key.revision=1;
    let original=state.context.take();state.context=Some(Arc::new(NativeContext {revision:1,project_id:"data-project".into(),registry_generation:7,
        project:root.clone(),draft:b"{}".to_vec(),platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Full}));
    assert!(!material.current(&state,&identity,7,&root));state.context=original;
    for flag in 0..4 {
        match flag {0=>state.lock_pending=true,1=>state.retiring=true,2=>state.unknown=true,_=>state.stopping=true};
        assert!(!material.current(&state,&identity,7,&root));
        state.lock_pending=false;state.retiring=false;state.unknown=false;state.stopping=false;
    }
    assert!(material.current(&state,&identity,7,&root));
    invalidate_all(&mut state);assert!(!material.current(&state,&identity,7,&root));
    assert!(state.assignments[0].holding.is_none() && !state.assignment_retirement.empty());
}
#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn public_assignment_projection_never_extends_private_payload_lifetime() {
    let (mut state,_identity,material)=data();let weak=Arc::downgrade(&material.holding.payload);
    let count=Arc::strong_count(&material.holding.payload);let status=DocumentBinding::status_data(&state,true);
    let copy=status.assignments.clone();assert_eq!(Arc::strong_count(&material.holding.payload),count);
    let public=serde_json::to_value(&status).unwrap();let text=serde_json::to_string(&public).unwrap();
    assert!(!text.contains("fictional-not-a-credential") && !text.contains("holding") && !text.contains("\"payload\":"));
    assert_eq!(public["assignments"][0].as_object().unwrap().len(),5);
    invalidate_all(&mut state);state.records.clear();drop(material);assert!(weak.upgrade().is_some());
    let retired=std::mem::take(&mut state.assignment_retirement);assert!(!retired.empty());drop(retired);
    assert!(weak.upgrade().is_none());assert_eq!(copy.len(),1);drop((copy,status));
}
#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn consent_expiry_transfers_original_loan_to_bounded_retirement_not_public_status() {
    use crate::github_input_group_session::{State,Consent};
    let (_document,identity,material)=data();let mut state=State::new();let end=Instant::now();
    let consent=|| Consent {prepared:wire::test_data::prepared(),end,session_id:"data-session".into(),project_id:"data-project".into(),
        generation:7,root:material.native.project.clone(),material:material.clone(),revoked:false,runner:None};
    state.consent=Some(consent());state.expire_consent(end);assert!(state.consent.is_none());
    assert!(!state.material_settled() && state.retirement_pending() && state.memory_reserved());
    assert!(!state.native_work_pending());assert!(state.materials().any(|value|Arc::ptr_eq(value,&material)));
    state.consent=Some(consent());state.revoke_consent(); // Second registered cell.
    state.consent=Some(consent());state.revoke_consent(); // Overflow preserves original third loan and refuses.
    assert!(state.exhausted && state.consent.as_ref().is_some_and(|v|v.revoked));
    let old=state.take_retirement(&identity);assert!(!old.empty());let receipt=old.dispose();state.finish_retirement(receipt);state.revoke_consent();
    assert!(state.consent.is_none() && !state.material_settled());let receipt=state.take_retirement(&identity).dispose();state.finish_retirement(receipt);assert!(state.material_settled());
}

#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn positive_finality_waits_for_actual_action_loan_drop_not_retirement_transfer() {
    use crate::github_input_group_session::{State,Consent};
    for later_unknown in [false,true] {
        let (_document,identity,material)=data();let mut state=State::new();let prepared=wire::test_data::prepared();
        let marker=prepared.target.marker.clone();let id="finished-original-operation";
        state.consent=Some(Consent {prepared:prepared.clone(),end:Instant::now(),session_id:"session".into(),project_id:"project".into(),
            generation:7,root:material.native.project.clone(),material:material.clone(),revoked:false,runner:None});
        state.revoke_consent(); // The same registered material book used by a finished active loan.
        state.view.reason=wire::Reason::None;
        state.view.operation=Some(wire::Operation {id:id.into(),kind:wire::Kind::Apply.into(),phase:wire::Phase::Settled,reason:wire::Reason::None});
        let write=wire::RemoteWrite::AcknowledgedCreated {status_code:201};
        state.retain_record(wire::test_data::record(&marker,write.clone()),wire::Completion {
            journal:wire::Settlement::Confirmed,cleanup:wire::Settlement::Confirmed,finality:wire::Finality::Settled},wire::Reason::None).unwrap();
        state.defer_material_finality(Some(id),Some(&marker));
        assert_eq!(state.view.operation.as_ref().unwrap().phase,wire::Phase::Running);
        assert!(!state.view.available && state.view.reason==wire::Reason::Busy && state.view.prepared.is_none());
        assert_eq!(state.view.records[0].completion.cleanup,wire::Settlement::Pending);
        assert_eq!(state.view.records[0].completion.finality,wire::Finality::Pending);
        assert_eq!(state.view.records[0].completion.journal,wire::Settlement::Confirmed);assert_eq!(state.view.records[0].write,write);
        let book=state.take_retirement(&identity);assert!(!book.empty());assert!(state.retirement_pending() && !state.material_settled());
        let snapshot=state.snapshot();assert_eq!(snapshot.records[0].completion.finality,wire::Finality::Pending);
        let receipt=book.dispose(); // Still no publication before this receipt enters its original State.
        assert!(state.retirement_pending() && !state.material_settled());assert_eq!(state.view.records[0].completion.finality,wire::Finality::Pending);
        if later_unknown {state.unknown();}
        state.finish_retirement(receipt);assert!(state.material_settled() && !state.retirement_pending());
        assert_eq!(state.view.operation.as_ref().unwrap().phase,if later_unknown {wire::Phase::CleanupUnknown} else {wire::Phase::Settled});
        assert_eq!(state.view.records[0].completion.cleanup,if later_unknown {wire::Settlement::Unknown} else {wire::Settlement::Confirmed});
        assert_eq!(state.view.records[0].completion.finality,if later_unknown {wire::Finality::Unknown} else {wire::Finality::Settled});
        assert_eq!(state.view.records[0].completion.journal,wire::Settlement::Confirmed);assert_eq!(state.view.records[0].write,write);
    }
}

#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn failed_apply_admission_defers_its_not_attempted_row_without_inventing_a_ticket() {
    use crate::github_input_group_session::{State,Consent};
    let (_document,identity,material)=data();let mut state=State::new();let prepared=wire::test_data::prepared();let marker=prepared.target.marker.clone();
    state.consent=Some(Consent {prepared,end:Instant::now(),session_id:"session".into(),project_id:"project".into(),generation:7,
        root:material.native.project.clone(),material,revoked:false,runner:None});
    state.view.operation=Some(wire::Operation {id:"old-prepare".into(),kind:wire::Kind::Prepare.into(),phase:wire::Phase::Settled,reason:wire::Reason::None});
    state.retain_record(wire::test_data::record(&marker,wire::RemoteWrite::NotAttempted),wire::Completion {
        journal:wire::Settlement::NotRun,cleanup:wire::Settlement::Confirmed,finality:wire::Finality::Settled},wire::Reason::RuntimeUnavailable).unwrap();
    state.revoke_consent();state.defer_material_finality(None,Some(&marker));
    assert_eq!(state.view.operation.as_ref().unwrap().id,"old-prepare");assert_eq!(state.view.operation.as_ref().unwrap().phase,wire::Phase::Settled);
    assert_eq!(state.view.records[0].completion.finality,wire::Finality::Pending);assert_eq!(state.view.records[0].write,wire::RemoteWrite::NotAttempted);
    let receipt=state.take_retirement(&identity).dispose();assert!(!state.material_settled());state.finish_retirement(receipt);
    assert!(state.material_settled());assert_eq!(state.view.records[0].completion.finality,wire::Finality::Settled);
    assert_eq!(state.view.records[0].completion.journal,wire::Settlement::NotRun);assert_eq!(state.view.records[0].reason,wire::Reason::RuntimeUnavailable);
    assert_eq!(state.view.operation.as_ref().unwrap().id,"old-prepare");
}

#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
#[test]
fn runner_context_keeps_weak_original_identity_without_an_assignment_or_payload_loan() {
    let (mut state,identity,material)=data();
    let original_context=Arc::downgrade(state.context.as_ref().unwrap());
    let context=GitHubRunnerContext {document:Arc::downgrade(&identity),native:original_context.clone(),revision:1,generation:7,
        root:material.native.project.clone(),native_config_sha256:wire::digest(b"{}")};
    let payload=Arc::downgrade(&material.holding.payload);let before=Arc::strong_count(&material.holding.payload);
    assert!(context.current(&state,&identity) && context.matches_material(&material));
    assert_eq!(Arc::strong_count(&material.holding.payload),before);
    assert!(!context.current(&state,&Arc::new(())));
    state.lock_pending=true;assert!(!context.current(&state,&identity));state.lock_pending=false;
    let saved=state.context.take();
    state.context=Some(Arc::new(NativeContext {revision:1,project_id:"data-project".into(),registry_generation:7,
        project:context.root.clone(),draft:b"{}".to_vec(),platform:Platform::Android,stage:Stage::Candidate,purpose:Purpose::Full}));
    assert!(!context.current(&state,&identity));state.context=saved;
    // Individual assignment removal does not require another network inventory
    // for the unchanged original context, and this read owns no private loan.
    state.assignments.clear();state.records.clear();drop(material);
    assert!(payload.upgrade().is_none());assert!(context.current(&state,&identity));
    state.context=None;assert!(original_context.upgrade().is_none());
    assert!(!context.current(&state,&identity));
}
