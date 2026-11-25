//! Closed signed input/Review correspondence; native material still comes
//! from the ordinary document borrower and the original Prepared/Session.
use super::*;
use crate::agent_android_build::signed as data;

pub(super) fn selection(s: &android_wire::SigningSelection) -> Result<data::Selection, BridgeError> {
    if !(1..=2).contains(&s.assignments.len()) { return Err(failure()); }
    let mut assignments = Vec::new();
    assignments.try_reserve_exact(s.assignments.len()).map_err(|_| failure())?;
    for row in &s.assignments {
        assignments.push(data::Assignment {
            kind: match row.kind.as_str() {
                "android-keystore" => data::Kind::AndroidKeystore,
                "android-firebase" => data::Kind::AndroidFirebase,
                _ => return Err(failure()),
            },
            record_id: service::Id::parse(&row.record_id).map_err(|_| failure())?,
            record_revision: row.record_revision, context_revision: row.context_revision,
        });
    }
    let result = data::Selection { mode: data::SigningMode::LocalUploadKey, assignments };
    if !result.valid() { return Err(failure()); }
    Ok(result)
}
pub(super) fn fixed(input: &android_wire::Prepare) -> bool {
    (input.operation.is_none() && input.action.is_none()
        || input.operation == Some(android_wire::Operation::AndroidCandidateInputs)
            && input.action == Some(android_wire::CreateAction::Create))
        && input.artifact_validation.mode == android_wire::ValidationMode::UploadSignature
        && input.artifact_validation.upload_certificate_sha256.as_deref().and_then(data::fingerprint).is_some()
        && input.signing.as_ref().is_some_and(|s| selection(s).is_ok())
}
pub(super) fn same(c: &android_wire::Context, review: &agent::Review) -> bool {
    (match (c.operation, c.action, &review.mode) {
        (android_wire::Operation::AndroidBuildSign, None, agent::Mode::SavedAndroidLocalUploadKeySign)
        | (android_wire::Operation::AndroidCandidateInputs, Some(android_wire::CreateAction::Create), agent::Mode::SavedAndroidCandidateInputs) => true,
        _ => false,
    })
        && c.artifact_validation.mode == android_wire::ValidationMode::UploadSignature
        && c.signing.as_ref().and_then(|s| selection(s).ok()).as_ref() == review.signing.as_ref()
        && c.artifact_validation.upload_certificate_sha256.as_deref().and_then(data::fingerprint)
            == review.upload_certificate_sha256
}

impl Approval {
    /// Added signed comparison allocations only. Baseline Approval/Grant roots
    /// remain in the existing ancillary quote; no private payload is copied.
    pub(crate) fn signing_backing(&self) -> Option<usize> {
        Self::signing_backing_data(&self.input, &self.review)
    }
    pub(crate) fn signing_backing_data(input: &android_wire::Prepare, review: &agent::Review) -> Option<usize> {
        let Some(policy) = &input.signing else { return Some(0); };
        if policy.assignments.capacity() > 2 { return None; }
        let n = policy.assignments.iter().try_fold(policy.assignments.capacity()
            .checked_mul(std::mem::size_of::<android_wire::SigningAssignment>())?, |n, row| {
                if row.kind.capacity() > 32 || row.record_id.capacity() > 64 { return None; }
                n.checked_add(row.kind.capacity())?.checked_add(row.record_id.capacity())
            })?;
        n.checked_add(input.artifact_validation.upload_certificate_sha256.as_ref()?.capacity())?
            .checked_mul(2)? // Original policy plus one contemporaneous Context-policy comparison.
            .checked_add(review.signing.as_ref()?.heap_bytes()?)?
            .checked_add(review.upload_certificate_sha256.as_ref()?.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_signed_input_requires_exact_closed_assignment_and_separate_scope() {
        let context=android_wire::tests::signed_context();
        let mut value=serde_json::to_value(&context).unwrap();
        value.as_object_mut().unwrap().remove("platform");value.as_object_mut().unwrap().remove("operation");
        let input=android_wire::prepare(&value).unwrap();assert!(fixed(&input));assert!(!super::super::fixed(&input));
        let selected=selection(input.signing.as_ref().unwrap()).unwrap();
        let review=agent::Review {mode:agent::Mode::SavedAndroidLocalUploadKeySign,signing:Some(selected),
            upload_certificate_sha256:input.artifact_validation.upload_certificate_sha256.as_deref().and_then(data::fingerprint),
            saved_config:agent::Config {bytes:input.saved_config.bytes,sha256:input.saved_config.sha256.clone()},
            saved_version:version(&input.saved_version),tools:agent::Tools {instance:service::Id::parse(&"b".repeat(32)).unwrap(),catalog_generation:1,record_sha256:"c".repeat(64)} };
        assert!(same(&input.context(),&review));
        let mut changed=input.clone();changed.operation=Some(android_wire::Operation::AndroidCandidateInputs);changed.action=Some(android_wire::CreateAction::Create);
        assert!(fixed(&changed));assert!(!same(&changed.context(),&review));
        let mut candidate = review.clone();candidate.mode=agent::Mode::SavedAndroidCandidateInputs;
        assert!(same(&changed.context(),&candidate));assert!(!same(&input.context(),&candidate));
        changed=input.clone();changed.signing.as_mut().unwrap().assignments[0].record_revision+=1;
        assert!(!same(&changed.context(),&review));
        changed=input.clone();changed.signing.as_mut().unwrap().assignments[0].kind="apple-p12".into();assert!(!fixed(&changed));
        let mut no_key=input;no_key.signing=None;assert!(!fixed(&no_key));
        assert!(Approval::signing_backing_data(&changed,&review).is_some()); // Capacity DATA is never eligibility.
    }
}
