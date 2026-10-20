//! Complete original-journal comparison DATA. No read, reservation, recovered
//! native fact, POST consent or key loan can be constructed from these values.
use super::*;
use crate::apple_provisioning_journal::{AccountSnapshot, CertificateIssuanceRow,
    KeyGeneration, NativeSettlement, ProfileSaveState};

pub(crate) const CERTIFICATE_RECOVERY_LIMIT: usize = 32 * 1024;
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateRecoveryAttempt {
    reference: Reference, display_name: String, observed_at: String,
    status: AttemptStatus, reason: AttemptReason, native_settlement: NativeSettlement,
    cancellation_requested: bool, certificate_id: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateRecoveryHistory {
    schema_version: u32, scope: &'static str,
    pub(crate) attempts: Vec<CertificateRecoveryAttempt>,
    pub(crate) hidden_unresolved: u32,
}

pub(crate) fn certificate_recovery_scope_matches(row: &CertificateIssuanceRow, scope: &ScopeData) -> bool {
    let Some(certificate) = &scope.certificate else { return false; };
    let Ok(mut target) = certificate.target(&scope.target) else { return false; };
    // List an old name only as DATA. Explicit selection must repeat the FULL
    // target check below inside the next original native request.
    target.display_name = row.intent.target.display_name.clone();
    row.intent.context.account_ref == scope.provisioning.account_ref
        && row.intent.provenance.project_binding == scope.provenance.project_binding
        && row.intent.provenance.registered_root == scope.provenance.registered_root
        && row.intent.source_key == certificate.source_key && row.intent.target == target
}
pub(crate) fn certificate_recovery_history(account: &AccountSnapshot, scope: &ScopeData)
    -> Result<CertificateRecoveryHistory, BridgeError> {
    need(scope.certificate.is_some())?;
    let old = recovery_history(account, scope)?; // SAME combined32 cap, duplicate/account checks.
    let visible_unresolved = old.attempts.iter().filter(|row|
        row.native_settlement != NativeSettlement::Known || !matches!(row.status,
            AttemptStatus::Succeeded | AttemptStatus::Failed | AttemptStatus::Cancelled)).count();
    let mut hidden = old.hidden_unresolved.checked_add(u32::try_from(visible_unresolved).map_err(|_| invalid())?).ok_or_else(invalid)?;
    let mut attempts = Vec::with_capacity(account.certificate_rows.len());
    for row in &account.certificate_rows {
        let reference = Reference { operation_id: row.intent.provenance.operation_id.as_str().into(),
            owner_generation: row.intent.provenance.owner_generation.as_str().into() };
        need(reference.valid() && reference.operation_id == row.intent.context.operation_id
            && display_name(&row.intent.target.display_name) && timestamp_shape(&row.intent.observed_at))?;
        if !certificate_recovery_scope_matches(row, scope) { continue; }
        if row.unresolved() { hidden = hidden.checked_sub(1).ok_or_else(invalid)?; }
        attempts.push(CertificateRecoveryAttempt { reference,
            display_name: row.intent.target.display_name.clone(), observed_at: row.intent.observed_at.clone(),
            status: row.update.record.status, reason: row.update.record.reason,
            native_settlement: row.native_settlement, cancellation_requested: row.update.record.cancel_requested,
            certificate_id: row.update.record.response_resource_id.clone() });
    }
    attempts.sort_by(|a,b| b.observed_at.cmp(&a.observed_at).then_with(|| a.reference.operation_id.cmp(&b.reference.operation_id)));
    let result = CertificateRecoveryHistory { schema_version: 1, scope: "local-ios-certificate-attempts", attempts, hidden_unresolved: hidden };
    bounded(&result, CERTIFICATE_RECOVERY_LIMIT).map_err(|_| invalid())?;
    Ok(result)
}

pub(crate) fn certificate_prior(account: &AccountSnapshot, scope: &ScopeData, reference: &Reference)
    -> Result<CertificatePriorData, BridgeError> {
    let certificate = scope.certificate.as_ref().ok_or_else(invalid)?;
    let target = certificate.target(&scope.target)?;
    // Validate the full original roster even when selecting just one row.
    recovery_history(account, scope)?;
    let row = account.certificate_rows.iter().find(|row|
        row.intent.provenance.operation_id.as_str() == reference.operation_id
            && row.intent.provenance.owner_generation.as_str() == reference.owner_generation).ok_or_else(invalid)?;
    need(certificate_recovery_scope_matches(row, scope) && row.intent.target == target)?;
    Ok(CertificatePriorData { reference: reference.clone(), source_key: row.intent.source_key.clone(),
        target: row.intent.target.clone(), csr_sha256: row.intent.csr_sha256.clone(),
        public_key_sha256: row.intent.public_key_sha256.clone(), record: row.update.record.clone(),
        receipt: row.update.receipt.clone() })
}

pub(crate) fn certificate_key_preparation(account: &AccountSnapshot, scope: &ScopeData)
    -> Result<Option<CertificateKeyPreparation>, BridgeError> {
    let certificate = scope.certificate.as_ref().ok_or_else(invalid)?;
    recovery_history(account, scope)?;
    let mut result = None;
    for row in &account.key_rows {
        if row.intent.destination != certificate.source_key { continue; }
        // An old keySaved ACK is only an additional account/team history gate.
        // Actual key material MUST come from this operation's fresh Load/Check.
        if result.is_some() || row.unresolved() || row.native_settlement != NativeSettlement::Known
            || row.intent.context.account_ref != scope.provisioning.account_ref
            || row.intent.target.team_id != scope.target.team_id
            || row.intent.target.app_id_prefix != scope.target.app_id_prefix
            || row.update.generation != KeyGeneration::Returned || row.update.save != ProfileSaveState::ReadBack
            || row.update.saved_reference.as_ref() != Some(&certificate.source_key) {
            return Ok(None);
        }
        let output = row.update.output.as_ref().ok_or_else(invalid)?;
        result = Some(CertificateKeyPreparation {
            reference: Reference { operation_id: row.intent.provenance.operation_id.as_str().into(),
                owner_generation: row.intent.provenance.owner_generation.as_str().into() },
            source_key: row.intent.destination.clone(), account_ref: row.intent.context.account_ref.clone(),
            team_id: row.intent.target.team_id.clone(), csr_sha256: output.csr_sha256.clone(),
            public_key_sha256: output.public_key_sha256.clone(), update_sha256: row.update.sha256().map_err(|_| invalid())?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::certificate::tests::{binding,row};
    use crate::apple_provisioning_journal::{KeyAlgorithm, KeyDisposition, KeyOutputMetadata,
        KeyPrepareIntent, KeyPrepareRow, KeyPrepareUpdate};

    fn account(scope:&ScopeData)->AccountSnapshot {
        AccountSnapshot { revision:crate::application_state_store::Revision(7),account:scope.provisioning.account_ref.clone(),
            rows:vec![],profile_rows:vec![],key_rows:vec![],certificate_rows:vec![] }
    }
    #[test]
    fn certificate_history_is_redacted_current_fullref_data_and_preserves_pending() {
        let binding=binding(Mode::CertificateReview);let mut account=account(&binding.scope);
        let mut old=row(&binding);old.intent.target.display_name="Explicit previous name".into();
        account.certificate_rows.push(old.clone());
        let history=certificate_recovery_history(&account,&binding.scope).unwrap();
        assert_eq!(history.attempts.len(),1);assert_eq!(history.hidden_unresolved,0);
        let data=serde_json::to_value(&history).unwrap();
        assert_eq!(data["attempts"][0]["displayName"],"Explicit previous name");
        assert_eq!(data["attempts"][0]["nativeSettlement"],"pending");
        let encoded=data.to_string();
        for private in ["sourceKey","sourceP8","accountRef","publicKeySha256","csrSha256","possibleSend","registeredRoot"] {
            assert!(!encoded.contains(private));
        }
        let reference=history.attempts[0].reference.clone();
        assert!(certificate_prior(&account,&binding.scope,&reference).is_err()); // Name is an explicit local choice, not silently rewritten.
        assert!(account.certificate_rows[0]==old && account.certificate_rows[0].unresolved());
    }
    #[test]
    fn certificate_history_does_not_disclose_other_key_project_root_team_or_account() {
        for field in 0..7 {
            let binding=binding(Mode::CertificateReview);let mut account=account(&binding.scope);
            let mut old=row(&binding);
            match field {
                0=>old.intent.source_key.revision_id="f".repeat(32),
                1=>old.intent.source_key.vault_id="f".repeat(32),
                2=>old.intent.provenance.project_binding.project_id=Id::parse(&"f".repeat(32)).unwrap(),
                3=>old.intent.provenance.registered_root.inode+=1,
                4=>old.intent.target.team_id="OTHERTEAM1".into(),
                5=>old.intent.target.entitlements_sha256="f".repeat(64),
                _=>old.intent.context.account_ref=crate::apple_provisioning_journal::AccountRef::from_selected_issuer([2;16]),
            }
            account.certificate_rows.push(old);
            if field==6 { assert!(certificate_recovery_history(&account,&binding.scope).is_err()); }
            else { let history=certificate_recovery_history(&account,&binding.scope).unwrap();
                assert!(history.attempts.is_empty() && history.hidden_unresolved==1); }
        }
    }
    #[test]
    fn certificate_prior_keeps_original_unknown_and_whole_roster_refuses_duplicates_or_overflow() {
        let binding=binding(Mode::CertificateReview);let mut account=account(&binding.scope);
        let mut old=row(&binding);old.native_settlement=NativeSettlement::Unknown;
        account.certificate_rows.push(old.clone());
        let reference=Reference { operation_id:old.intent.context.operation_id.clone(),
            owner_generation:old.intent.provenance.owner_generation.as_str().into() };
        let prior=certificate_prior(&account,&binding.scope,&reference).unwrap();
        assert!(prior.record==old.update.record && prior.receipt.is_none());
        assert!(account.certificate_rows[0].native_settlement==NativeSettlement::Unknown);
        account.certificate_rows.push(old);
        assert!(certificate_prior(&account,&binding.scope,&reference).is_err());
        account.certificate_rows.truncate(1);
        for n in 1..=32 {
            let mut row=account.certificate_rows[0].clone();
            row.intent.context.operation_id=format!("{:032x}",n+100);
            row.intent.provenance.operation_id=Id::parse(&row.intent.context.operation_id).unwrap();
            account.certificate_rows.push(row);
        }
        assert!(certificate_recovery_history(&account,&binding.scope).is_err());
    }

    fn saved_key(binding:&RequestBinding)->KeyPrepareRow {
        let certificate=row(binding).intent;
        let mut context=certificate.context;context.operation_id="6".repeat(32);
        let mut provenance=certificate.provenance;provenance.operation_id=Id::parse(&context.operation_id).unwrap();
        provenance.owner_generation=Id::parse(&"7".repeat(32)).unwrap();
        let intent=KeyPrepareIntent { context,provenance,target:certificate.target,source_p8:certificate.source_p8,
            destination:certificate.source_key.clone(),algorithm:KeyAlgorithm::Rsa2048Sha256,bundle:certificate.bundle,
            observed_at:certificate.observed_at,valid_until:certificate.valid_until,before_sha256:certificate.before_sha256,
            review_plan_sha256:"b".repeat(64) };
        KeyPrepareRow { intent, generator_armed:true, update:KeyPrepareUpdate { sequence:3,
            generation:KeyGeneration::Returned,output:Some(KeyOutputMetadata { frame_bytes:4000,frame_sha256:"c".repeat(64),
                csr_sha256:certificate.csr_sha256,public_key_sha256:certificate.public_key_sha256 }),
            save:ProfileSaveState::ReadBack,saved_reference:Some(certificate.source_key),
            disposition:KeyDisposition::Cancelled,cancel_requested:true },native_settlement:NativeSettlement::Known }
    }
    #[test]
    fn key_saved_history_is_extra_fullref_gate_not_current_loan_or_restored_authority() {
        let binding=binding(Mode::CertificateReview);let mut account=account(&binding.scope);
        account.key_rows.push(saved_key(&binding));
        let found=certificate_key_preparation(&account,&binding.scope).unwrap().unwrap();
        assert!(found.source_key==binding.scope.certificate.as_ref().unwrap().source_key);
        // A preserved cancelled local save can be loaded afresh, but Pending,
        // unknown, another key revision or another team supplies no such gate.
        for field in 0..4 {
            let mut changed=saved_key(&binding);
            match field {
                0=>changed.native_settlement=NativeSettlement::Pending,
                1=>changed.update.save=ProfileSaveState::Unknown,
                2=>changed.intent.destination.revision_id="f".repeat(32),
                _=>changed.intent.target.team_id="OTHERTEAM1".into(),
            }
            account.key_rows=vec![changed];
            assert!(certificate_key_preparation(&account,&binding.scope).unwrap().is_none());
        }
    }
}
