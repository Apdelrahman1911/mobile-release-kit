//! Child of the existing vault, reusing its ORIGINAL tests' loan fixtures and
//! actual bind_payload/retirement functions. All receipt/assessment inputs here
//! are explicitly synthetic DATA, not native Bind/keyring/signing evidence.
use super::tests::{loan_state, publish_loan_data, same_backing_loan};
use super::*;
use serde_json::json;

fn id(byte: u8) -> format::Id {
    format::Id::from_bytes([byte; 16]).unwrap()
}

fn assessment_data() -> SafeAssessment {
    let mut fields = vec![
        json!({"id":"file", "requirement":"MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
        "presence":"supplied", "state":"configured", "issues":[],
        "checks":[{"scope":"jks-header", "outcome":"asserted-pass"}]}),
    ];
    for (id, requirement) in [
        ("storePassword", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"),
        ("keyAlias", "MOBILE_RELEASE_ANDROID_KEY_ALIAS"),
        ("keyPassword", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"),
    ] {
        let mut checks = vec![json!({"scope":"value-admission", "outcome":"passed"})];
        if id == "keyAlias" {
            checks.push(json!({"scope":"identifier-format", "outcome":"passed"}));
        }
        fields.push(json!({"id":id, "requirement":requirement, "presence":"supplied", "state":"configured", "issues":[], "checks":checks}));
    }
    let result: AssessmentResult = serde_json::from_value(json!({"schemaVersion":1, "policyVersion":"credential-policy-v1",
        "kind":"android-keystore", "context":{"platform":"android", "stage":"candidate", "purpose":"signing"},
        "applicability":{"state":"required", "reason":"selected"}, "state":"configured", "fields":fields,
        "identity":"not-applicable", "assurance":{"basis":"supplied-input-only", "scalarValuesProcessed":true,
        "fileObservationsProcessed":true, "selectedFilesRead":false, "keyringAccessed":false, "storageWritesPerformed":false,
        "projectCodeExecuted":false, "sourceCustody":"not-established", "nativeValidation":"not-run",
        "serviceValidation":"not-run", "releaseReadiness":"unknown"}})).ok().unwrap();
    SafeAssessment(Arc::new(result))
}
pub(super) fn bound_data() -> DocumentState {
    let mut state = loan_state();
    let context = state.context.as_ref().unwrap();
    state.context = Some(Arc::new(NativeContext {
        execution_mode: context.execution_mode,
        revision: context.revision,
        project_id: context.project_id.clone(),
        project: context.project.clone(),
        registry_generation: context.registry_generation,
        draft: context.draft.clone(),
        platform: Platform::Android,
        stage: Stage::Candidate,
        purpose: Purpose::Signing,
    }));
    publish_loan_data(&mut state, Kind::AndroidKeystore, 3);
    let slot = state.slot.as_mut().unwrap();
    slot.owner.set_endpoint(None);
    slot.assessment = Some(assessment_data());
    state
}
fn remembered(state: &DocumentState) -> Option<StoredRef> {
    assignment_native::remembered_bound_reference(
        state,
        state.slot.as_ref().unwrap(),
        Kind::AndroidKeystore,
    )
}

#[test]
fn actual_bound_loan_remains_the_reference_after_ordinary_working_reference_retirement() {
    let mut state = bound_data();
    let original = remembered(&state).expect("synthetic current loan");
    let mut slot = state.slot.take().unwrap();
    let retired = take_retirement(&mut state, &mut slot);
    assert!(slot.vault.reference.is_none()); // The actual previously broken interaction.
    assert!(slot.owner.vault.lock().unwrap().key.is_none());
    assert!(retired.loaded.is_none());
    drop(retired);
    state.slot = Some(slot);
    let current =
        remembered(&state).expect("same actual retained BoundLoan, not the retired work ref");
    assert!(
        current.identity == original.identity
            && current.record == original.record
            && current.revision == original.revision
            && current.original == original.original
    );
}

#[test]
fn persisted_choice_cannot_use_counter_alias_replaced_context_or_duplicate_loan() {
    let mut state = bound_data();
    assert!(remembered(&state).is_some());
    let session = state.vault.as_mut().unwrap();
    let revision = session.rows[0].authenticated.revision;
    session.rows[0].authenticated.revision =
        format::Revision::new(id(202), revision.counter).unwrap();
    assert!(remembered(&state).is_none());
    state.vault.as_mut().unwrap().rows[0].authenticated.revision = revision;
    assert!(remembered(&state).is_some());
    let extra = same_backing_loan(state.vault.as_ref().unwrap().bound[0].as_ref().unwrap());
    state.vault.as_mut().unwrap().bound[1] = Some(extra);
    assert!(remembered(&state).is_none());
    state.vault.as_mut().unwrap().bound[1] = None;
    let original = state.context.as_ref().unwrap();
    state.context = Some(Arc::new(NativeContext {
        execution_mode: original.execution_mode,
        revision: original.revision,
        project_id: original.project_id.clone(),
        project: original.project.clone(),
        registry_generation: original.registry_generation,
        draft: original.draft.clone(),
        platform: original.platform,
        stage: original.stage,
        purpose: original.purpose,
    }));
    assert!(remembered(&state).is_none()); // Equal DTO/context numbers do not preserve the original Arc.
}

#[test]
fn assignment_shaped_data_is_insufficient_without_settled_original_bind_and_assessment() {
    let mut state = bound_data();
    let assessment = state.slot.as_mut().unwrap().assessment.take();
    assert!(remembered(&state).is_none());
    state.slot.as_mut().unwrap().assessment = assessment;
    state.slot.as_mut().unwrap().settlement = Settlement::Unknown;
    assert!(remembered(&state).is_none());
    state.slot.as_mut().unwrap().settlement = Settlement::Known;
    state
        .slot
        .as_ref()
        .unwrap()
        .owner
        .coordinator
        .lock()
        .unwrap()
        .receipt = JoinReceipt::Failed;
    assert!(remembered(&state).is_none());
}
