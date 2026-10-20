//! Historical, public DATA from the original journal read. This module never
//! opens state, restores a reservation, issues consent, or changes an attempt.
//! Only the original positive Review retirement may publish its output.
use super::{display_name, invalid, need, timestamp_shape, Reference, ScopeData};
use crate::{
    apple_provisioning_journal::{
        AccountSnapshot, AttemptReason, AttemptStatus, JournalRow, NativeSettlement, ROWS,
    },
    edit_protocol::bounded,
    error::BridgeError,
};
use serde::Serialize;
use std::collections::BTreeSet;

pub(crate) const RECOVERY_LIMIT: usize = 32 * 1024;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryAttempt {
    pub(crate) reference: Reference,
    pub(crate) display_name: String,
    pub(crate) observed_at: String,
    pub(crate) status: AttemptStatus,
    pub(crate) reason: AttemptReason,
    pub(crate) native_settlement: NativeSettlement,
    pub(crate) cancellation_requested: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryHistory {
    schema_version: u32,
    scope: &'static str,
    pub(crate) attempts: Vec<RecoveryAttempt>,
    // Details of other projects/identities never cross this boundary. They
    // still participate in the original issuer-wide reserve fence.
    pub(crate) hidden_unresolved: u32,
}

/// Comparison against genuine current ScopeData is repeated by the original
/// native request builder before a Reconcile worker can receive its prior row.
/// The explicit old display-name selection is checked separately by the
/// existing FULL target equality; it is never a saved-config rewrite.
pub(crate) fn recovery_scope_matches(row: &JournalRow, scope: &ScopeData) -> bool {
    let old = &row.intent;
    old.context.account_ref == scope.provisioning.account_ref
        && old.provenance.project_binding == scope.provenance.project_binding
        && old.provenance.registered_root == scope.provenance.registered_root
        && old.target.bundle_id == scope.target.bundle_id
        && old.target.team_id == scope.target.team_id
        && old.target.app_id_prefix == scope.target.app_id_prefix
        && old.target.existing_application == scope.target.existing_application
}

/// `AccountSnapshot` is the complete validated return of the SAME original
/// Initialize journal job, not a renderer value or a restored native receipt.
/// A caller with no such return must publish None, never an empty history.
pub(crate) fn recovery_history(
    account: &AccountSnapshot,
    scope: &ScopeData,
) -> Result<RecoveryHistory, BridgeError> {
    need(account.account == scope.provisioning.account_ref && account.rows.len() <= ROWS)?;
    let mut seen = BTreeSet::new();
    let mut attempts = Vec::with_capacity(account.rows.len());
    let mut hidden_unresolved = 0;
    for row in &account.rows {
        let reference = Reference {
            operation_id: row.intent.provenance.operation_id.as_str().into(),
            owner_generation: row.intent.provenance.owner_generation.as_str().into(),
        };
        // The journal already validated its immutable hashes and whole state.
        // Keep this separate public projection closed and bounded as well.
        need(
            row.intent.context.account_ref == account.account
                && reference.valid()
                && row.intent.context.operation_id == reference.operation_id
                && seen.insert(reference.operation_id.clone())
                && display_name(&row.intent.target.display_name)
                && timestamp_shape(&row.intent.observed_at),
        )?;
        if !recovery_scope_matches(row, scope) {
            if row.unresolved() {
                hidden_unresolved += 1;
            }
            continue;
        }
        attempts.push(RecoveryAttempt {
            reference,
            display_name: row.intent.target.display_name.clone(),
            observed_at: row.intent.observed_at.clone(),
            status: row.attempt.record.status,
            reason: row.attempt.record.reason,
            native_settlement: row.native_settlement,
            cancellation_requested: row.attempt.record.cancel_requested,
        });
    }
    // Deterministic display only, not an automatic selection or latest-result
    // authority. Canonical UTC timestamps retain their original precision.
    attempts.sort_by(|a, b| {
        b.observed_at
            .cmp(&a.observed_at)
            .then_with(|| a.reference.operation_id.cmp(&b.reference.operation_id))
    });
    let history = RecoveryHistory {
        schema_version: 1,
        scope: "local-ios-bundle-attempts",
        attempts,
        hidden_unresolved,
    };
    bounded(&history, RECOVERY_LIMIT).map_err(|_| invalid())?;
    Ok(history)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        apple_provisioning_journal::{AccountRef, BundleRegistrationIntent, NativeProvenance},
        application_state_store::Revision,
        service_protocol::Id,
    };
    use serde_json::json;

    // Synthetic comparison DATA only. These hash-shaped values do NOT pass
    // the actual journal validator and never create native state/authority.
    pub(crate) fn sample() -> (AccountSnapshot, ScopeData) {
        let account = AccountRef::from_selected_issuer([1; 16]);
        let context = json!({"projectId":"runtime-alias","clientId":"old-desktop",
            "operationId":"a".repeat(32),"observationRevision":1,"accountRef":account,
            "credentialRecordId":"b".repeat(32),"credentialRevision":1,"credentialContextRevision":1});
        let provenance: NativeProvenance = serde_json::from_value(json!({
            "projectBinding":{"projectId":"c".repeat(32),"canonicalRoot":"/synthetic/project","device":1,"inode":2},
            "operationId":"a".repeat(32),"ownerGeneration":"d".repeat(32),"registrationGeneration":1,
            "registeredRoot":{"path":"/synthetic/project","device":1,"inode":2,"mode":16832,"uid":501,"gid":20},
            "draftRevision":1,"baselineGeneration":1,"savedConfig":{"bytes":2,"sha256":"e".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":2,"sha256":"f".repeat(64),"name":"1.0","build":1}
        })).unwrap();
        let target = json!({"bundleId":"com.example.app","teamId":"ABCDE12345","appIdPrefix":"ABCDE12345",
            "displayName":"Previous app name","existingApplication":false});
        let intent: BundleRegistrationIntent = serde_json::from_value(json!({"context":context,"provenance":provenance,
            "target":target,"observedAt":"2026-10-19T12:34:56+00:00","validUntil":"2026-10-19T12:39:56+00:00",
            "beforeSha256":"1".repeat(64),"planSha256":"2".repeat(64),"requestBodySha256":"3".repeat(64)})).unwrap();
        let row = serde_json::from_value(json!({"intent":intent,"sendArmed":true,"nativeSettlement":"unknown",
            "attempt":{"sequence":2,"record":{"context":context,"planSha256":"2".repeat(64),"action":"register_bundle_id",
                "status":"unknown","reason":"provider_outcome_unknown","possibleSend":true,"responseResourceId":null,
                "responseResourceSha256":null,"observedResourceId":null,"cancelRequested":false}}})).unwrap();
        let mut scope = ScopeData {
            provisioning: intent.context.clone(),
            provenance,
            target: intent.target,
            reviewed_at: None,
        };
        scope.provisioning.project_id = "new-runtime-alias".into();
        scope.provisioning.credential_record_id = "9".repeat(32);
        scope.target.display_name = "Current explicit name".into();
        (
            AccountSnapshot {
                revision: Revision(7),
                account,
                rows: vec![row],
            },
            scope,
        )
    }

    #[test]
    fn historical_selection_preserves_unknown_and_drops_private_descriptors() {
        let (account, scope) = sample();
        let history = recovery_history(&account, &scope).unwrap();
        assert!(history.attempts.len() == 1 && history.hidden_unresolved == 0);
        assert!(history.attempts[0].native_settlement == NativeSettlement::Unknown);
        assert!(history.attempts[0].display_name == "Previous app name");
        let value = serde_json::to_value(history).unwrap();
        assert!(value.as_object().unwrap().len() == 4);
        assert!(value["attempts"][0].as_object().unwrap().len() == 7);
        let text = value.to_string();
        for forbidden in [
            "accountRef",
            "credentialRecordId",
            "canonicalRoot",
            "sha256",
            "sendArmed",
            "possibleSend",
        ] {
            assert!(!text.contains(forbidden));
        }
        assert!(account.revision == Revision(7) && account.rows[0].unresolved());
    }

    #[test]
    fn every_current_native_scope_field_is_required_even_with_same_runtime_alias() {
        let (account, scope) = sample();
        for field in 0..14 {
            let mut changed = ScopeData {
                provisioning: scope.provisioning.clone(),
                provenance: scope.provenance.clone(),
                target: scope.target.clone(),
                reviewed_at: None,
            };
            match field {
                0 => {
                    changed.provenance.project_binding.project_id =
                        Id::parse(&"4".repeat(32)).unwrap()
                }
                1 => changed.provenance.registered_root.path.push_str("-other"),
                2 => changed.provenance.registered_root.device += 1,
                3 => changed.provenance.registered_root.inode += 1,
                4 => changed.provenance.registered_root.mode ^= 1,
                5 => changed.provenance.registered_root.uid += 1,
                6 => changed.provenance.registered_root.gid += 1,
                7 => changed.target.bundle_id.push_str(".other"),
                8 => changed.target.team_id = "ZYXWV98765".into(),
                9 => changed.target.app_id_prefix = "ZYXWV98765".into(),
                10 => changed.target.existing_application = true,
                11 => changed
                    .provenance
                    .project_binding
                    .canonical_root
                    .push_str("-other"),
                12 => changed.provenance.project_binding.device += 1,
                _ => changed.provenance.project_binding.inode += 1,
            }
            assert!(!recovery_scope_matches(&account.rows[0], &changed));
            let history = recovery_history(&account, &changed).unwrap();
            assert!(history.attempts.is_empty() && history.hidden_unresolved == 1);
        }
        let mut changed = scope;
        changed.provisioning.account_ref = AccountRef::from_selected_issuer([2; 16]);
        assert!(recovery_history(&account, &changed).is_err());
    }

    #[test]
    fn mixed_account_or_duplicate_roster_never_becomes_an_empty_history() {
        let (mut account, scope) = sample();
        account.rows[0].intent.context.account_ref = AccountRef::from_selected_issuer([2; 16]);
        assert!(recovery_history(&account, &scope).is_err());
        let (mut account, scope) = sample();
        account.rows.push(account.rows[0].clone());
        assert!(recovery_history(&account, &scope).is_err());
        account.rows.clear();
        let empty = recovery_history(&account, &scope).unwrap();
        assert!(empty.attempts.is_empty() && empty.hidden_unresolved == 0);
    }

    #[test]
    fn full_public_roster_is_bounded_without_dropping_older_attempts() {
        let (mut account, scope) = sample();
        let original = account.rows.remove(0);
        for i in 1..=ROWS {
            let mut row = original.clone();
            row.intent.context.operation_id = format!("{i:032x}");
            row.intent.provenance.operation_id =
                Id::parse(&row.intent.context.operation_id).unwrap();
            row.attempt.record.context.operation_id = row.intent.context.operation_id.clone();
            row.intent.target.display_name = "🧪".repeat(128);
            account.rows.push(row);
        }
        let history = recovery_history(&account, &scope).unwrap();
        assert!(history.attempts.len() == ROWS);
        assert!(bounded(&history, RECOVERY_LIMIT).unwrap().len() < RECOVERY_LIMIT);
        account.rows.push(original);
        assert!(recovery_history(&account, &scope).is_err());
    }
}
