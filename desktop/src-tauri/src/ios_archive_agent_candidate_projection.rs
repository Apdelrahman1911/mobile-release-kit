//! Borrow the actual candidate's private build fields after full native checks.
use super::*;
use crate::{agent_candidate_build as candidate, agent_ios_archive as agent};

impl ResultValue {
    pub(crate) fn agent_candidate_report(
        &self,
        context: &Context,
        operation: &str,
    ) -> Result<agent::Report, BridgeError> {
        let Self::Candidate(v) = self else {
            return Err(protocol_error());
        };
        if !context.valid() || !context.candidate() || !self.valid(context, operation) {
            return Err(protocol_error());
        }
        let c = &v.candidate_inputs;
        let summary = candidate::Candidate {
            operation_id: c.operation_id.clone(),
            head_sequence: v.head_sequence,
            candidate_sha256: c.candidate_sha256.clone(),
            source_commit: c.source_commit.clone(),
            source_tree: c.source_tree.clone(),
            primary_bytes: c.files[0].bytes,
            primary_sha256: c.files[0].sha256.clone(),
        };
        let pairing = v.build.pairing.as_ref().ok_or_else(protocol_error)?;
        let report = agent::Report {
            scope: agent::Scope::LocalIosCandidateInputs,
            used_config: agent::Config {
                bytes: v.build.used_config.bytes,
                sha256: v.build.used_config.sha256.clone(),
            },
            used_version: agent::Version {
                bytes: v.build.used_version.bytes,
                sha256: v.build.used_version.sha256.clone(),
                name: v.build.used_version.name.clone(),
                build: v.build.used_version.build,
            },
            entries: v.build.entries,
            bytes: v.build.bytes,
            export: Some(agent::signed::Export {
                ipa_bytes: v.build.ipa_bytes.ok_or_else(protocol_error)?,
                pairing: agent::signed::Pairing {
                    native_paths: pairing.native_paths,
                    native_identities: pairing.native_identities,
                    present_symbol_slices: pairing.present_symbol_slices,
                },
            }),
            candidate: Some(summary),
        };
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
    fn original_ios_candidate_decoder_preserves_operation_and_primary_without_ordinary_conversion()
    {
        let context = super::super::tests::candidate_context();
        let raw = super::super::tests::candidate_complete();
        let terminal =
            super::super::terminal(&raw, &context, super::super::tests::CANDIDATE_ID).unwrap();
        let value = terminal.result.as_ref().unwrap();
        assert!(value.ordinary_build().is_none());
        let report = value
            .agent_candidate_report(&context, super::super::tests::CANDIDATE_ID)
            .unwrap();
        assert!(report.valid());
        assert_eq!(report.scope, agent::Scope::LocalIosCandidateInputs);
        let summary = report.candidate.as_ref().unwrap();
        assert!(summary.matches_operation(super::super::tests::CANDIDATE_ID));
        assert_eq!(
            summary.primary_bytes,
            report.export.as_ref().unwrap().ipa_bytes
        );
        assert!(serde_json::to_vec(summary).unwrap().len() <= candidate::BYTES);
        assert!(value
            .agent_candidate_report(&context, &"a".repeat(32))
            .is_err());
        assert!(value
            .agent_candidate_report(
                &super::super::tests::signed_context(),
                super::super::tests::CANDIDATE_ID
            )
            .is_err());
        let signed = super::super::terminal(
            &super::super::tests::signed_complete(),
            &super::super::tests::signed_context(),
            &"a".repeat(32),
        )
        .unwrap();
        assert!(signed
            .result
            .unwrap()
            .agent_candidate_report(&context, super::super::tests::CANDIDATE_ID)
            .is_err());
        for field in ["sourceCommit", "sourceTree", "candidateSha256"] {
            let mut changed = raw.clone();
            changed["result"]["candidateInputs"][field] = serde_json::json!("wrong");
            assert!(
                super::super::terminal(&changed, &context, super::super::tests::CANDIDATE_ID)
                    .is_err()
            );
        }
        let mut changed = raw.clone();
        changed["result"]["headSequence"] = serde_json::json!(514);
        assert!(
            super::super::terminal(&changed, &context, super::super::tests::CANDIDATE_ID).is_err()
        );
        let mut changed = raw;
        changed["result"]["candidateInputs"]["files"][0]["bytes"] = serde_json::json!(513);
        assert!(
            super::super::terminal(&changed, &context, super::super::tests::CANDIDATE_ID).is_err()
        );
    }
    #[test]
    fn native_ios_candidate_origin_roundtrips_without_weakening_other_mode_guards() {
        let raw = serde_json::json!({"schemaVersion":2,"statusRevision":1,"availability":"available",
            "modeCapabilities":{"unsigned":true,"signed":true,"recovery":false,"signingCheck":false},
            "operation":{"operationId":super::super::tests::CANDIDATE_ID,"ownerGeneration":"b".repeat(32),
                "context":super::super::tests::candidate_context(),"phase":"awaiting-consent","intentUsable":true,
                "outcome":null,"reason":"none","stage":null,"activity":null,"disposition":null,"result":null,
                "agentIosArchive":{"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)}}});
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
                0 => {
                    c.as_object_mut().unwrap().remove("action");
                }
                1 => c["action"] = serde_json::json!("check-signing"),
                2 => c["operation"] = serde_json::json!("ios-signed-export"),
                3 => c["signing"] = serde_json::Value::Null,
                _ => {
                    c["operation"] = serde_json::json!("ios-signing-inputs-check");
                    c["action"] = serde_json::json!("check-signing");
                }
            }
            assert!(status(&wrong).is_err());
        }
    }
}
