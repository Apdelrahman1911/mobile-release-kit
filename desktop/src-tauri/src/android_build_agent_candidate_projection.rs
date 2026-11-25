//! Project only a validated SAME candidate variant; no Build/context conversion.
use super::*;
use crate::agent_android_build as agent;

impl Context {
    /// Closed native status/agent correspondence. The full original Context
    /// parser still validates the saved inputs and entire signing selection.
    pub(crate) fn agent_context(&self) -> bool {
        self.valid()
            && match (self.operation, self.action) {
                (Operation::AndroidBuildInspect, None) => {
                    self.signing.is_none()
                        && self.artifact_validation.mode == ValidationMode::StructureAndVersion
                        && self.artifact_validation.upload_certificate_sha256.is_none()
                }
                (Operation::AndroidBuildSign, None)
                | (Operation::AndroidCandidateInputs, Some(CreateAction::Create)) => {
                    self.signing
                        .as_ref()
                        .is_some_and(|s| s.mode == SigningMode::LocalUploadKey)
                        && self.artifact_validation.mode == ValidationMode::UploadSignature
                }
                _ => false,
            }
    }
}

impl ResultValue {
    pub(crate) fn agent_candidate_report(
        &self,
        context: &Context,
        operation: &str,
    ) -> Result<agent::Report, BridgeError> {
        let Self::Candidate(value) = self else {
            return Err(protocol_error());
        };
        if !context.valid()
            || !context.candidate()
            || !self.valid()
            || !self.matches_operation(operation)
        {
            return Err(protocol_error());
        }
        let uuid = candidate_uuid(operation).ok_or_else(protocol_error)?;
        let candidate = value
            .candidate_inputs
            .agent_candidate(&uuid, value.head_sequence)
            .ok_or_else(protocol_error)?;
        let mut report = agent_signed::signed_build_report(&value.build, context)?;
        report.scope = agent::Scope::LocalAndroidCandidateInputs;
        report.candidate = Some(candidate);
        if !report.valid() {
            return Err(protocol_error());
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_status_and_serializer_accept_only_the_three_exact_agent_modes() {
        let marker = serde_json::json!({"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
        for context in [
            super::super::tests::context(),
            super::super::tests::signed_context(),
            super::super::tests::candidate_context(),
        ] {
            let operation = if context.candidate() {
                super::super::tests::CANDIDATE_ID
            } else {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            };
            let raw = serde_json::json!({"schemaVersion":1,"statusRevision":1,"availability":"available",
                "operation":{"operationId":operation,"ownerGeneration":"b".repeat(32),"context":context,
                    "phase":"awaiting-consent","intentUsable":true,"outcome":null,"reason":"none","stage":null,
                    "activity":null,"disposition":null,"result":null,"agentAndroidBuild":marker}});
            let parsed = status(&raw).unwrap();
            let bytes = status_bytes(&parsed).unwrap();
            assert_eq!(
                status(&serde_json::from_slice(&bytes).unwrap()).unwrap(),
                parsed
            );
            for change in 0..5 {
                let mut wrong = raw.clone();
                let c = &mut wrong["operation"]["context"];
                match change {
                    0 => c["operation"] = serde_json::json!("android-build-sign"),
                    1 => c["action"] = serde_json::json!("check-signing"),
                    2 => c["artifactValidation"]["mode"] = serde_json::json!("upload-signature"),
                    3 => c["signing"] = serde_json::json!(null),
                    _ => c["action"] = serde_json::json!("create"),
                }
                // An unchanged exact signed/candidate cell is not a negative.
                if wrong == raw {
                    continue;
                }
                assert!(status(&wrong).is_err(), "{change}: {context:?}");
            }
        }
    }
    #[test]
    fn original_candidate_decoder_not_signed_output_supplies_the_compact_report() {
        let context = super::super::tests::candidate_context();
        let raw = super::super::tests::candidate_complete();
        let terminal = super::super::terminal(&raw, &context).unwrap();
        let value = terminal.result.as_ref().unwrap();
        let report = value
            .agent_candidate_report(&context, super::super::tests::CANDIDATE_ID)
            .unwrap();
        assert!(report.valid());
        assert_eq!(report.scope, agent::Scope::LocalAndroidCandidateInputs);
        let candidate = report.candidate.as_ref().unwrap();
        assert!(candidate.matches_operation(super::super::tests::CANDIDATE_ID));
        assert_eq!(candidate.primary_bytes, report.artifact.size);
        assert_eq!(candidate.primary_sha256, report.artifact.sha256);
        assert!(
            serde_json::to_vec(candidate).unwrap().len() <= crate::agent_candidate_build::BYTES
        );
        assert!(value
            .agent_candidate_report(&context, &"a".repeat(32))
            .is_err());
        assert!(value
            .agent_candidate_report(
                &super::super::tests::signed_context(),
                super::super::tests::CANDIDATE_ID
            )
            .is_err());
        assert!(value.agent_signed_report(&context).is_err());
        let signed = super::super::terminal(
            &super::super::tests::signed_complete(),
            &super::super::tests::signed_context(),
        )
        .unwrap();
        assert!(signed
            .result
            .unwrap()
            .agent_candidate_report(&context, super::super::tests::CANDIDATE_ID)
            .is_err());
        for path in ["sourceCommit", "sourceTree", "candidateSha256"] {
            let mut changed = raw.clone();
            changed["result"]["candidateInputs"][path] = serde_json::json!("wrong");
            assert!(super::super::terminal(&changed, &context).is_err());
        }
        let mut changed = raw.clone();
        changed["result"]["headSequence"] = serde_json::json!(514);
        assert!(super::super::terminal(&changed, &context).is_err());
        let mut changed = raw;
        changed["result"]["candidateInputs"]["files"][0]["sha256"] =
            serde_json::json!("1".repeat(64));
        assert!(super::super::terminal(&changed, &context).is_err());
    }
}
