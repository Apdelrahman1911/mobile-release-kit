//! Borrow the already validated SAME native terminal, without serializing or
//! copying its source paths, task labels, material or full result envelope.
use super::*;
use crate::agent_android_build as agent;
use agent::signed;
fn status(value: CoreStatus) -> agent::FindingStatus {
    match value {
        CoreStatus::Pass => agent::FindingStatus::Pass, CoreStatus::Fail => agent::FindingStatus::Fail,
        CoreStatus::Missing => agent::FindingStatus::Missing, CoreStatus::Blocked => agent::FindingStatus::Blocked,
        CoreStatus::Invalid => agent::FindingStatus::Invalid, CoreStatus::Skip => agent::FindingStatus::Skip,
        CoreStatus::Manual => agent::FindingStatus::Manual, CoreStatus::Configured => agent::FindingStatus::Configured,
        CoreStatus::NotApplicable => agent::FindingStatus::NotApplicable,
    }
}
fn check(value: CheckId) -> agent::Check {
    match value {
        CheckId::AabStructure => agent::Check::AabStructure, CheckId::AabManifest => agent::Check::AabManifest,
        CheckId::ApplicationId => agent::Check::ApplicationId, CheckId::BuildNumber => agent::Check::BuildNumber,
        CheckId::VersionName => agent::Check::VersionName, CheckId::ReleaseFlags => agent::Check::ReleaseFlags,
        CheckId::Signature => agent::Check::Signature, CheckId::Signer => agent::Check::Signer,
        CheckId::CoreLifecycle => agent::Check::CoreLifecycle, CheckId::OtherCoreFinding => agent::Check::OtherCoreFinding,
    }
}
impl ResultValue {
    pub(crate) fn agent_signed_report(&self, context: &Context) -> Result<agent::Report, BridgeError> {
        let Self::Build(value) = self else { return Err(protocol_error()); };
        if context.operation != Operation::AndroidBuildSign || !context.valid() || !self.valid() {
            return Err(protocol_error());
        }
        signed_build_report(value, context)
    }
}
pub(super) fn signed_build_report(value: &ResultData, context: &Context) -> Result<agent::Report, BridgeError> {
        if !value.valid() || value.signing != Some(SigningMode::LocalUploadKey)
            || value.used_config != context.saved_config || value.used_version != context.saved_version
            || value.artifact_validation != context.artifact_validation
        { return Err(protocol_error()); }
        let upload_certificate_sha256 = context.artifact_validation.upload_certificate_sha256.as_deref()
            .and_then(signed::fingerprint).ok_or_else(protocol_error)?;
        let artifact = value.artifacts.first().ok_or_else(protocol_error)?;
        let mut findings = Vec::new();
        findings.try_reserve_exact(value.findings.len()).map_err(|_| protocol_error())?;
        for row in &value.findings {
            findings.push(agent::Finding { ordinal: row.ordinal, check: check(row.check), status: status(row.status) });
        }
        let mut counts = std::collections::BTreeMap::new();
        for native in CORE_STATUSES {
            counts.insert(status(native), value.summary.counts.0[CoreCounts::index(native)].ok_or_else(protocol_error)?);
        }
        let report = agent::Report {
            scope: agent::Scope::LocalPostBuildArtifactObservation,
            used_config: agent::Config { bytes: value.used_config.bytes, sha256: value.used_config.sha256.clone() },
            used_version: agent::Version { bytes: value.used_version.bytes, sha256: value.used_version.sha256.clone(),
                name: value.used_version.name.clone(), build: value.used_version.build },
            findings, summary: agent::Summary { total: value.summary.total, shown: value.summary.shown,
                omitted: value.summary.omitted, counts },
            artifact: agent::Artifact { size: artifact.size, sha256: artifact.sha256.clone() },
            candidate: None,
            signing: Some(signed::Report { mode: signed::SigningMode::LocalUploadKey, upload_certificate_sha256,
                signature: signed::Signature::Passed, signer: signed::Signer::MatchesSavedUploadCertificate }),
        };
        // These two fixed assurances follow ONLY value.valid()'s exact native
        // signed success branch. A failed native result=None is never created.
        if !report.valid() { return Err(protocol_error()); }
        Ok(report)
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returned_signed_result_is_projected_without_paths_and_preserves_raw_policy_match() {
        let context = crate::android_build_protocol::tests::signed_context();
        let original = crate::android_build_protocol::tests::signed_complete();
        let terminal = terminal(&original, &context).unwrap();
        let value = terminal.result.as_ref().unwrap();
        let report = value.agent_signed_report(&context).unwrap();
        assert!(report.valid());
        assert_eq!(report.signing.as_ref().unwrap().upload_certificate_sha256, "aa".repeat(32));
        let encoded = serde_json::to_value(&report).unwrap();
        for field in ["selection", "command", "toolchainSelection", "fileName", "password", "recordId", "source"] {
            assert!(!serde_json::to_string(&encoded).unwrap().contains(field));
        }
        assert_eq!(report.findings.len(), 4);
        let mut changed = context.clone();
        changed.artifact_validation.upload_certificate_sha256 = Some("aa".repeat(32));
        // Canonical fingerprints match, but a different saved raw policy is
        // never substituted for the original full native Context.
        assert!(value.agent_signed_report(&changed).is_err());
        changed = context.clone(); changed.saved_version.build += 1;
        assert!(value.agent_signed_report(&changed).is_err());
        assert!(value.agent_signed_report(&crate::android_build_protocol::tests::context()).is_err());
    }
    #[test]
    fn failed_signature_or_missing_original_close_never_becomes_a_signed_report() {
        let context = crate::android_build_protocol::tests::signed_context();
        let good = crate::android_build_protocol::tests::signed_complete();
        for field in ["materialRetired", "buildInputsClosed", "inputClosed", "invocationClosed"] {
            let mut value = good.clone(); value["lifetime"][field] = serde_json::json!(false);
            assert!(terminal(&value, &context).is_err());
        }
        let mut value = good;
        value["result"]["findings"][3]["status"] = serde_json::json!("FAIL");
        value["result"]["summary"]["counts"]["PASS"] = serde_json::json!(3);
        value["result"]["summary"]["counts"]["FAIL"] = serde_json::json!(1);
        value["result"]["assurances"]["signer"] = serde_json::json!("failed");
        assert!(result(&value["result"]).is_err());
    }
}
