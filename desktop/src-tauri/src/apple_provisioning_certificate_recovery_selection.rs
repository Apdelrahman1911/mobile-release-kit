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

fn certificate_project_scope_matches(row: &CertificateIssuanceRow, scope: &ScopeData) -> bool {
    let Some(certificate) = &scope.certificate else { return false; };
    let Ok(mut target) = certificate.target(&scope.target) else { return false; };
    // List an old name only as DATA. Explicit selection must repeat the FULL
    // target check below inside the next original native request.
    target.display_name = row.intent.target.display_name.clone();
    row.intent.context.account_ref == scope.provisioning.account_ref
        && row.intent.provenance.project_binding == scope.provenance.project_binding
        && row.intent.provenance.registered_root == scope.provenance.registered_root
        && row.intent.target == target
}
pub(crate) fn certificate_recovery_scope_matches(row: &CertificateIssuanceRow, scope: &ScopeData) -> bool {
    certificate_project_scope_matches(row, scope)
        && scope.certificate.as_ref().is_some_and(|certificate| row.intent.source_key == certificate.source_key)
}
/// Optional hashes are comparison DATA from the caller's actually returned
/// key check. The native publisher separately requires its original ACK and
/// full retirement; this projection cannot grant a key loan or reconciliation.
pub(crate) fn certificate_recovery_history(account: &AccountSnapshot, scope: &ScopeData,
    checked_key: Option<(&str, &str)>)
    -> Result<CertificateRecoveryHistory, BridgeError> {
    need(scope.certificate.is_some() && checked_key.is_none_or(|(csr, spki)| sha(csr) && sha(spki)))?;
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
        let same_key = checked_key.is_some_and(|(csr, spki)| row.intent.csr_sha256 == csr
            && row.intent.public_key_sha256 == spki && certificate_project_scope_matches(row, scope));
        if !certificate_recovery_scope_matches(row, scope) && !same_key { continue; }
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

pub(crate) fn certificate_prior(account: &AccountSnapshot, scope: &ScopeData, context: &Context)
    -> Result<CertificatePriorData, BridgeError> {
    need(context.mode == Mode::CertificateReconcile)?;
    let reference = context.reference.as_ref().ok_or_else(invalid)?;
    need(reference.valid())?;
    let certificate = scope.certificate.as_ref().ok_or_else(invalid)?;
    let target = certificate.target(&scope.target)?;
    // Validate the full original roster even when selecting just one row.
    recovery_history(account, scope)?;
    let row = account.certificate_rows.iter().find(|row|
        row.intent.provenance.operation_id.as_str() == reference.operation_id
            && row.intent.provenance.owner_generation.as_str() == reference.owner_generation).ok_or_else(invalid)?;
    // Select immutable historical DATA only. A different current full ref is
    // not an alias for this row: the SAME new operation must independently
    // compare its real key/CSR with both old hashes before the first GET.
    need(certificate_project_scope_matches(row, scope) && row.intent.target == target
        && row.intent.source_key.validate().is_ok())?;
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
        let recovered=account.key_recovery(row).map_err(|_|invalid())?;
        if result.is_some() || account.key_unresolved(row).map_err(|_|invalid())?
            || row.native_settlement != NativeSettlement::Known && recovered.is_none()
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
            recovery: recovered.map(|record|Ok::<_,BridgeError>(CertificateRecoveredKey {
                stamp:KeyRecoveryStamp{reference:Reference{operation_id:record.provenance.operation_id.as_str().into(),
                    owner_generation:record.provenance.owner_generation.as_str().into()},sha256:record.sha256().map_err(|_|invalid())?},
                output:record.output.clone()})).transpose()?,
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
            rows:vec![],profile_rows:vec![],key_rows:vec![],certificate_rows:vec![],p12_rows:vec![],key_recoveries:vec![] }
    }
    fn reconcile_context(binding: &RequestBinding, reference: Reference) -> Context {
        let mut context = binding.context.clone();
        context.mode = Mode::CertificateReconcile;
        context.reference = Some(reference);
        context
    }
    fn restored_selection(binding: &mut std::sync::Arc<RequestBinding>) {
        let binding = std::sync::Arc::get_mut(binding).unwrap();
        let certificate = binding.scope.certificate.as_mut().unwrap();
        certificate.source_key = crate::credential_setup::KeyReference { vault_id:"a".repeat(32), generation_id:"b".repeat(32),
            record_id:"e".repeat(32), revision_id:"d".repeat(32), revision_counter:1 };
        certificate.source_p8.vault_id = certificate.source_key.vault_id.clone();
        certificate.source_p8.generation_id = certificate.source_key.generation_id.clone();
        certificate.key_preparation = None;
        binding.context.key_record_id = Some(certificate.source_key.record_id.clone());
        binding.context.key_record_revision = Some(1);
    }
    #[test]
    fn restored_key_history_compares_both_hashes_without_rewriting_old_rows_or_key_saved() {
        let mut binding = binding(Mode::CertificateReview);
        let mut account = account(&binding.scope);
        let mut old = row(&binding);
        old.native_settlement = NativeSettlement::Unknown;
        account.certificate_rows.push(old.clone());
        account.key_rows.push(saved_key(&binding));
        restored_selection(&mut binding);
        assert!(certificate_key_preparation(&account,&binding.scope).unwrap().is_none());
        let hashes = Some((old.intent.csr_sha256.as_str(),old.intent.public_key_sha256.as_str()));
        let hidden = certificate_recovery_history(&account,&binding.scope,None).unwrap();
        assert!(hidden.attempts.is_empty() && hidden.hidden_unresolved == 1);
        let shown = certificate_recovery_history(&account,&binding.scope,hashes).unwrap();
        assert!(shown.attempts.len() == 1 && shown.hidden_unresolved == 0);
        for (csr,spki) in [("e".repeat(64),old.intent.public_key_sha256.clone()),
            (old.intent.csr_sha256.clone(),"e".repeat(64))] {
            let shown = certificate_recovery_history(&account,&binding.scope,Some((&csr,&spki))).unwrap();
            assert!(shown.attempts.is_empty() && shown.hidden_unresolved == 1);
        }
        let context = reconcile_context(&binding,shown.attempts[0].reference.clone());
        let prior = certificate_prior(&account,&binding.scope,&context).unwrap();
        assert!(prior.source_key == old.intent.source_key);
        assert!(prior.source_key != binding.scope.certificate.as_ref().unwrap().source_key);
        assert!(prior.record == old.update.record && prior.receipt == old.update.receipt);
        assert!(account.certificate_rows[0] == old && account.certificate_rows[0].unresolved());
        assert!(account.key_rows[0].intent.destination == old.intent.source_key);
        assert!(certificate_prior(&account,&binding.scope,&binding.context).is_err());
    }
    #[test]
    fn restored_key_hashes_cannot_disclose_foreign_project_root_or_target() {
        for field in 0..7 {
            let mut binding = binding(Mode::CertificateReview);
            let mut account = account(&binding.scope);
            let mut old = row(&binding);
            let (csr,spki) = (old.intent.csr_sha256.clone(),old.intent.public_key_sha256.clone());
            match field {
                0 => old.intent.provenance.project_binding.project_id = Id::parse(&"f".repeat(32)).unwrap(),
                1 => old.intent.provenance.registered_root.inode += 1,
                2 => old.intent.target.team_id = "OTHERTEAM1".into(),
                3 => old.intent.target.app_id_prefix = "OTHERTEAM1".into(),
                4 => old.intent.target.bundle_id = "com.other.fixture".into(),
                5 => old.intent.target.entitlements_sha256 = "f".repeat(64),
                _ => old.intent.context.account_ref = crate::apple_provisioning_journal::AccountRef::from_selected_issuer([2;16]),
            }
            let reference = Reference { operation_id:old.intent.context.operation_id.clone(),
                owner_generation:old.intent.provenance.owner_generation.as_str().into() };
            account.certificate_rows.push(old);
            restored_selection(&mut binding);
            let history = certificate_recovery_history(&account,&binding.scope,Some((&csr,&spki)));
            if field == 6 { assert!(history.is_err()); }
            else { let history = history.unwrap(); assert!(history.attempts.is_empty() && history.hidden_unresolved == 1); }
            assert!(certificate_prior(&account,&binding.scope,&reconcile_context(&binding,reference)).is_err());
        }
    }
    #[test]
    fn restored_prior_stays_reconcile_only_and_both_key_hashes_are_rechecked() {
        let mut binding = binding(Mode::CertificateReview);
        let mut account = account(&binding.scope);
        let old = row(&binding);
        let reference = Reference { operation_id:old.intent.context.operation_id.clone(),
            owner_generation:old.intent.provenance.owner_generation.as_str().into() };
        account.certificate_rows.push(old.clone());
        restored_selection(&mut binding);
        let context = reconcile_context(&binding,reference);
        let prior = certificate_prior(&account,&binding.scope,&context).unwrap();
        let binding = std::sync::Arc::get_mut(&mut binding).unwrap();
        binding.context = context;
        binding.scope.certificate.as_mut().unwrap().prior = Some(prior);
        let certificate = binding.scope.certificate.as_ref().unwrap();
        assert!(certificate.valid(&binding.context,&binding.scope));
        // This is the exact DATA comparison used AFTER native Loan matching
        // in key_ack; it cannot construct that loan or a returned ACK.
        assert!(certificate.prior_key_matches(Mode::CertificateReconcile,&old.intent.csr_sha256,&old.intent.public_key_sha256));
        assert!(!certificate.prior_key_matches(Mode::CertificateReconcile,&"f".repeat(64),&old.intent.public_key_sha256));
        assert!(!certificate.prior_key_matches(Mode::CertificateReconcile,&old.intent.csr_sha256,&"f".repeat(64)));
        for mode in [Mode::CertificateReview,Mode::CertificateCreate,Mode::KeyPrepare,Mode::P12Review,Mode::P12Save] {
            let mut context = binding.context.clone(); context.mode = mode;
            assert!(!certificate.valid(&context,&binding.scope));
            assert!(!certificate.prior_key_matches(mode,&old.intent.csr_sha256,&old.intent.public_key_sha256));
        }
        binding.scope.certificate.as_mut().unwrap().prior.as_mut().unwrap().source_key.revision_id = "0".repeat(32);
        assert!(!binding.scope.certificate.as_ref().unwrap().valid(&binding.context,&binding.scope));
        account.certificate_rows[0].intent.source_key.revision_id = "0".repeat(32);
        assert!(certificate_prior(&account,&binding.scope,&binding.context).is_err());
    }
    #[test]
    fn certificate_history_is_redacted_current_fullref_data_and_preserves_pending() {
        let binding=binding(Mode::CertificateReview);let mut account=account(&binding.scope);
        let mut old=row(&binding);old.intent.target.display_name="Explicit previous name".into();
        account.certificate_rows.push(old.clone());
        let history=certificate_recovery_history(&account,&binding.scope,None).unwrap();
        assert_eq!(history.attempts.len(),1);assert_eq!(history.hidden_unresolved,0);
        let data=serde_json::to_value(&history).unwrap();
        assert_eq!(data["attempts"][0]["displayName"],"Explicit previous name");
        assert_eq!(data["attempts"][0]["nativeSettlement"],"pending");
        let encoded=data.to_string();
        for private in ["sourceKey","sourceP8","accountRef","publicKeySha256","csrSha256","possibleSend","registeredRoot"] {
            assert!(!encoded.contains(private));
        }
        let reference=history.attempts[0].reference.clone();
        assert!(certificate_prior(&account,&binding.scope,&reconcile_context(&binding,reference)).is_err()); // Name is an explicit local choice, not silently rewritten.
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
            if field==6 { assert!(certificate_recovery_history(&account,&binding.scope,None).is_err()); }
            else { let history=certificate_recovery_history(&account,&binding.scope,None).unwrap();
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
        let context=reconcile_context(&binding,reference);
        let prior=certificate_prior(&account,&binding.scope,&context).unwrap();
        assert!(prior.record==old.update.record && prior.receipt.is_none());
        assert!(account.certificate_rows[0].native_settlement==NativeSettlement::Unknown);
        account.certificate_rows.push(old);
        assert!(certificate_prior(&account,&binding.scope,&context).is_err());
        account.certificate_rows.truncate(1);
        for n in 1..=32 {
            let mut row=account.certificate_rows[0].clone();
            row.intent.context.operation_id=format!("{:032x}",n+100);
            row.intent.provenance.operation_id=Id::parse(&row.intent.context.operation_id).unwrap();
            account.certificate_rows.push(row);
        }
        assert!(certificate_recovery_history(&account,&binding.scope,None).is_err());
    }

    fn saved_key(binding:&RequestBinding)->KeyPrepareRow {
        let certificate=row(binding).intent;
        let mut context=certificate.context;context.operation_id="6".repeat(32);
        let mut provenance=certificate.provenance;provenance.operation_id=Id::parse(&context.operation_id).unwrap();
        provenance.owner_generation=Id::parse(&"7".repeat(32)).unwrap();
        let mut intent=KeyPrepareIntent { context,provenance,target:certificate.target,source_p8:certificate.source_p8,
            destination:certificate.source_key.clone(),algorithm:KeyAlgorithm::Rsa2048Sha256,bundle:certificate.bundle,
            observed_at:certificate.observed_at,valid_until:certificate.valid_until,before_sha256:certificate.before_sha256,
            review_plan_sha256:"b".repeat(64) };
        intent.review_plan_sha256=intent.review_hash().unwrap();
        let row=KeyPrepareRow { intent, generator_armed:true, update:KeyPrepareUpdate { sequence:3,
            generation:KeyGeneration::Returned,output:Some(KeyOutputMetadata { frame_bytes:4000,frame_sha256:"c".repeat(64),
                csr_sha256:certificate.csr_sha256,public_key_sha256:certificate.public_key_sha256 }),
            save:ProfileSaveState::ReadBack,saved_reference:Some(certificate.source_key),
            disposition:KeyDisposition::Cancelled,cancel_requested:true },native_settlement:NativeSettlement::Known };
        row.validate().unwrap();row
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

    #[test]
    fn durable_recovery_selection_keeps_pending_and_has_a_distinct_certificate_origin() {
        use crate::apple_provisioning_journal::{KeyRecoveryRecord,KeyRecoveryOrigin,key_row_sha256};
        let certificate = binding(Mode::CertificateReview);
        let mut account = account(&certificate.scope);
        let mut row = saved_key(&certificate);
        account.key_rows.push(row.clone());
        let normal = certificate_key_preparation(&account,&certificate.scope).unwrap().unwrap();
        assert!(normal.recovery.is_none());
        assert!(serde_json::to_value(&normal).unwrap().get("recovery").is_none());
        let mut scope = std::sync::Arc::try_unwrap(binding(Mode::CertificateReview)).ok().unwrap().scope;
        let source = scope.certificate.take().unwrap();
        scope.key = Some(KeyScopeData { source_p8:source.source_p8,source_key:Some(source.source_key),
            destination:None,entitlements:json!({}),review:None,vault_inventory:None,recovery:None });
        assert!(!key_recovery_selection(&account,&scope).unwrap().needs_record()); // Known: compare only.
        row.native_settlement=NativeSettlement::Pending;
        account.key_rows=vec![row.clone()];
        let original=serde_json::to_value(&row).unwrap();
        assert!(key_recovery_selection(&account,&scope).unwrap().needs_record());
        assert!(certificate_key_preparation(&account,&certificate.scope).unwrap().is_none());
        let record=KeyRecoveryRecord { context:scope.provisioning.clone(),provenance:scope.provenance.clone(),
            target:row.intent.target.clone(),source_p8:scope.key.as_ref().unwrap().source_p8.clone(),
            source_key:row.intent.destination.clone(),original:KeyRecoveryOrigin {
                operation_id:row.intent.provenance.operation_id.clone(),owner_generation:row.intent.provenance.owner_generation.clone(),
                row_sha256:key_row_sha256(&row).unwrap() },output:row.update.output.clone().unwrap() };
        record.matches_row(&row).unwrap();
        account.key_recoveries.push(record.clone());
        let selected=key_recovery_selection(&account,&scope).unwrap();
        assert!(!selected.needs_record() && selected.recovery.is_some());
        let recovered=certificate_key_preparation(&account,&certificate.scope).unwrap().unwrap();
        assert!(recovered.reference==normal.reference && recovered.update_sha256==normal.update_sha256);
        assert_eq!(recovered.recovery.unwrap().stamp.sha256,record.sha256().unwrap());
        assert!(account.key_rows[0].unresolved());
        assert_eq!(serde_json::to_value(&account.key_rows[0]).unwrap(),original);
        // Even the same public hashes cannot substitute a restored NEW ref.
        scope.key.as_mut().unwrap().source_key.as_mut().unwrap().revision_id="9".repeat(32);
        assert!(key_recovery_selection(&account,&scope).is_err());
        scope.key.as_mut().unwrap().source_key=Some(row.intent.destination.clone());
        account.key_recoveries[0].original.row_sha256="e".repeat(64);
        assert!(key_recovery_selection(&account,&scope).is_err());
        account.key_recoveries.clear();
        account.key_rows[0].native_settlement=NativeSettlement::Unknown;
        assert!(key_recovery_selection(&account,&scope).is_err());
        account.key_rows=vec![row.clone(),row];
        assert!(key_recovery_selection(&account,&scope).is_err());
    }
}
