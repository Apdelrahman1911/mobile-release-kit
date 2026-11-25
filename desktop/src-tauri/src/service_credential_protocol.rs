//! Closed comparison DATA for the three ordinary encrypted-credential actions.
//! Native kind/context and the actual preview remain the admission authority.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    AndroidKeystore,
    AndroidFirebase,
    AppleP12,
    AppleProfile,
    AscP8,
    IosFirebase,
    GoogleServiceAccount,
    ProjectReadToken,
    AppleReviewContact,
    AppleReviewDemo,
    OperationCommitment,
}
impl CredentialKind {
    // Existing Android Load/Bind keeps its original actions and native proof.
    pub(crate) fn general_assessment(self) -> bool { self != Self::AndroidKeystore }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_actions_are_new_only_scalar_data_and_distinct_from_android_authority() {
        let id = "a".repeat(32);
        for kind in ["android-firebase", "apple-p12", "apple-profile", "asc-p8", "ios-firebase",
            "google-service-account", "project-read-token", "apple-review-contact", "apple-review-demo", "operation-commitment"] {
            let value = serde_json::json!({"kind":"credential-import-prepared", "credentialKind":kind,
                "previewOperationId":7,"previewToken":id});
            let import: Selection = serde_json::from_value(value.clone()).unwrap();
            assert!(import.valid());
            assert_eq!(import.kind(), Kind::CredentialImportPrepared);
            assert_ne!(import.kind().consent(), Kind::GenerateNew.consent());
            for extra in ["password", "fields", "path", "label", "replacement", "declaration"] {
                let mut raw = value.clone(); raw[extra] = serde_json::json!("not-permitted");
                assert!(serde_json::from_value::<Selection>(raw).is_err());
            }
            let assess: Selection = serde_json::from_value(serde_json::json!({"kind":"credential-assess-existing",
                "credentialKind":kind,"recordId":id,"expectedRevision":1})).unwrap();
            assert!(assess.valid());
            assert_ne!(assess.kind().consent(), import.kind().consent());
        }
        for kind in ["apple-distribution-key", "google-wif", "unknown"] {
            assert!(serde_json::from_value::<CredentialKind>(serde_json::json!(kind)).is_err());
        }
        let old_key: Selection = serde_json::from_value(serde_json::json!({"kind":"credential-assess-existing",
            "credentialKind":"android-keystore","recordId":id,"expectedRevision":1})).unwrap();
        assert!(!old_key.valid());
    }

    #[test]
    fn imported_reference_is_new_unassigned_only_and_never_a_review_or_assignment() {
        let id = |n: u8| Id::parse(&format!("{n:032x}")).unwrap();
        let mut s = Status { schema_version:1, origin: Query { project_id:id(1), service_instance:id(2), request_id:id(3) },
            grant_id:id(4), kind:Kind::CredentialImportPrepared, state:State::ImportedUnassigned,
            settlement:Settlement::Settled, reason:Reason::None, asset_operation_id:Some(7), do_not_replay:true,
            key:Some(KeyReference { vault_id:id(5), generation_id:id(6), record_id:id(7), revision_id:id(8), revision_counter:1 }) };
        assert!(s.validate().is_ok());
        for kind in [Kind::GenerateNew, Kind::PrepareExisting, Kind::BindReviewed, Kind::CredentialAssessExisting, Kind::CredentialAssignReviewed] {
            s.kind=kind; assert!(s.validate().is_err());
        }
        s.kind=Kind::CredentialImportPrepared;
        s.key.as_mut().unwrap().revision_counter=2; assert!(s.validate().is_err());
        s.key.as_mut().unwrap().revision_counter=1;
        s.state=State::Assigned; assert!(s.validate().is_err());
        s.state=State::ReviewReady; s.key=None; assert!(s.validate().is_err());
    }
}
