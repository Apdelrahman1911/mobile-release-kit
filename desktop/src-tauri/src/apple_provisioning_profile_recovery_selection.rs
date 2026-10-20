//! Historical profile comparison DATA from the original, fully joined journal
//! read. No namespace access, restored save/POST permission, or join constructor.
use super::{display_name, invalid, need, recovery_history, timestamp_shape, Reference, ScopeData};
use crate::{
    apple_provisioning_journal::{
        AccountSnapshot, AttemptReason, AttemptStatus, NativeSettlement, ProfileAction,
        ProfileProvider, ProfileSaveState, ProfileSetupRow,
    },
    edit_protocol::bounded,
    error::BridgeError,
};
use serde::Serialize;

pub(crate) const PROFILE_RECOVERY_LIMIT: usize = 32 * 1024;

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum RecordedProvider {
    DownloadPending,
    DownloadReturned,
    DownloadRefused,
    DownloadUnknown,
    Creation {
        status: AttemptStatus,
        reason: AttemptReason,
    },
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileRecoveryAttempt {
    pub(crate) reference: Reference,
    pub(crate) display_name: String,
    pub(crate) observed_at: String,
    pub(crate) action: ProfileAction,
    pub(crate) provider: RecordedProvider,
    pub(crate) save: ProfileSaveState,
    pub(crate) native_settlement: NativeSettlement,
    pub(crate) cancellation_requested: bool,
    pub(crate) unresolved: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileRecoveryHistory {
    schema_version: u32,
    scope: &'static str,
    pub(crate) attempts: Vec<ProfileRecoveryAttempt>,
    pub(crate) hidden_unresolved: u32,
}

fn listed(row: &ProfileSetupRow, scope: &ScopeData) -> bool {
    let Some(signing) = &scope.signing else {
        return false;
    };
    let Ok(mut target) = signing.target(&scope.target) else {
        return false;
    };
    // Listing alone may show the old display name. The explicit UI selection
    // adopts only that text; unchanged profile_prior compares the FULL target
    // again inside the new original native request. No config is rewritten.
    target.display_name = row.intent.target.display_name.clone();
    row.intent.context.account_ref == scope.provisioning.account_ref
        && row.intent.provenance.project_binding == scope.provenance.project_binding
        && row.intent.provenance.registered_root == scope.provenance.registered_root
        && row.intent.source_key == signing.source_key
        && row.intent.target == target
}

pub(crate) fn profile_recovery_history(
    account: &AccountSnapshot,
    scope: &ScopeData,
) -> Result<ProfileRecoveryHistory, BridgeError> {
    need(scope.signing.is_some())?;
    // Reuse the existing account-wide roster validation, joint cap and hidden
    // unresolved-family census. Key/certificate families compose THERE. Never
    // reinterpret a missing/failed INITIAL return as an empty account.
    let old = recovery_history(account, scope)?;
    let visible_bundle_unresolved = old
        .attempts
        .iter()
        .filter(|row| {
            row.native_settlement != NativeSettlement::Known
                || !matches!(
                    row.status,
                    AttemptStatus::Succeeded | AttemptStatus::Failed | AttemptStatus::Cancelled
                )
        })
        .count() as u32;
    let mut hidden_unresolved = old
        .hidden_unresolved
        .checked_add(visible_bundle_unresolved)
        .ok_or_else(invalid)?;
    let mut attempts = Vec::with_capacity(account.profile_rows.len());
    for row in &account.profile_rows {
        let reference = Reference {
            operation_id: row.intent.provenance.operation_id.as_str().into(),
            owner_generation: row.intent.provenance.owner_generation.as_str().into(),
        };
        need(
            reference.valid()
                && reference.operation_id == row.intent.context.operation_id
                && display_name(&row.intent.target.display_name)
                && timestamp_shape(&row.intent.observed_at),
        )?;
        if !listed(row, scope) {
            continue;
        }
        let unresolved = row.unresolved();
        if unresolved {
            hidden_unresolved = hidden_unresolved.checked_sub(1).ok_or_else(invalid)?;
        }
        let provider = match &row.update.provider {
            ProfileProvider::DownloadPending => RecordedProvider::DownloadPending,
            ProfileProvider::DownloadReturned => RecordedProvider::DownloadReturned,
            ProfileProvider::DownloadRefused => RecordedProvider::DownloadRefused,
            ProfileProvider::DownloadUnknown => RecordedProvider::DownloadUnknown,
            ProfileProvider::Creation(record) => RecordedProvider::Creation {
                status: record.status,
                reason: record.reason,
            },
        };
        attempts.push(ProfileRecoveryAttempt {
            reference,
            display_name: row.intent.target.display_name.clone(),
            observed_at: row.intent.observed_at.clone(),
            action: row.intent.action,
            provider,
            save: row.update.save,
            native_settlement: row.native_settlement,
            cancellation_requested: row.update.cancel_requested,
            unresolved,
        });
    }
    attempts.sort_by(|a, b| {
        b.observed_at
            .cmp(&a.observed_at)
            .then_with(|| a.reference.operation_id.cmp(&b.reference.operation_id))
    });
    let history = ProfileRecoveryHistory {
        schema_version: 1,
        scope: "local-ios-profile-attempts",
        attempts,
        hidden_unresolved,
    };
    bounded(&history, PROFILE_RECOVERY_LIMIT).map_err(|_| invalid())?;
    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        apple_provisioning_journal::*, credential_setup::KeyReference, service_protocol::Id,
    };
    use serde_json::json;

    // Comparison-only fixture. These strings are not authenticated journal
    // content, a selected native P12, a provider resource, or a NativeJoined.
    fn sample() -> (AccountSnapshot, ScopeData) {
        let (mut account, mut scope) = super::super::recovery_selection::tests::sample();
        let old = account.rows.pop().unwrap().intent;
        let source_key = KeyReference {
            vault_id: "1".repeat(32),
            generation_id: "2".repeat(32),
            record_id: "3".repeat(32),
            revision_id: "4".repeat(32),
            revision_counter: 1,
        };
        let target = ProfileTarget {
            bundle_id: old.target.bundle_id.clone(),
            team_id: old.target.team_id.clone(),
            app_id_prefix: old.target.app_id_prefix.clone(),
            display_name: old.target.display_name.clone(),
            existing_application: old.target.existing_application,
            entitlements_sha256: profile_entitlements_sha256(&json!({})).unwrap(),
        };
        let mut destination = source_key.clone();
        destination.record_id = "5".repeat(32);
        destination.revision_id = "6".repeat(32);
        let intent = ProfileSetupIntent {
            context: old.context,
            provenance: old.provenance,
            target,
            action: ProfileAction::ReuseDownload,
            source_key: source_key.clone(),
            destination,
            bundle: ProfileBundle {
                resource_id: "fixture-bundle".into(),
                identifier: old.target.bundle_id,
                platform: "IOS".into(),
                seed_id: old.target.app_id_prefix,
            },
            certificate: ProfileCertificate {
                resource_id: "fixture-certificate".into(),
                certificate_type: "DISTRIBUTION".into(),
                not_before: "2026-10-01T00:00:00+00:00".into(),
                expires_at: "2027-10-01T00:00:00+00:00".into(),
                certificate_sha256: "7".repeat(64),
                public_key_sha256: "8".repeat(64),
            },
            profile: None,
            observed_at: old.observed_at,
            valid_until: old.valid_until,
            before_sha256: old.before_sha256,
            plan_sha256: old.plan_sha256,
            request_body_sha256: None,
        };
        account.profile_rows.push(ProfileSetupRow {
            intent,
            send_armed: false,
            native_settlement: NativeSettlement::Unknown,
            update: ProfileUpdate {
                sequence: 1,
                provider: ProfileProvider::DownloadUnknown,
                download: None,
                save: ProfileSaveState::NotEntered,
                saved_reference: None,
                cancel_requested: true,
            },
        });
        scope.target.display_name = "A new current display name".into();
        scope.signing = Some(super::super::ProfileScopeData {
            source_key,
            destination: None,
            expected_certificate_sha256: "7".repeat(64),
            p12_sha256: "9".repeat(64),
            entitlements: json!({}),
            review: None,
            prior: None,
        });
        (account, scope)
    }

    #[test]
    fn profile_history_selects_only_current_original_scope_without_restoring_authority() {
        let (account, mut scope) = sample();
        let history = profile_recovery_history(&account, &scope).unwrap();
        assert_eq!(history.attempts.len(), 1);
        assert!(history.attempts[0].unresolved);
        assert_eq!(history.hidden_unresolved, 0);
        let row = &account.profile_rows[0];
        assert!(!super::super::profile_recovery_scope_matches(row, &scope));
        scope.target.display_name = row.intent.target.display_name.clone();
        assert!(super::super::profile_recovery_scope_matches(row, &scope));
        let value = serde_json::to_value(&history).unwrap();
        assert_eq!(value["attempts"][0]["nativeSettlement"], "unknown");
        assert_eq!(value["attempts"][0]["save"], "not-entered");
        let encoded =
            String::from_utf8(bounded(&history, PROFILE_RECOVERY_LIMIT).unwrap()).unwrap();
        for private in [
            "sourceKey",
            "destination",
            "savedReference",
            "registeredRoot",
            "planSha256",
            "certificateSha256",
            "profileContent",
            "nativeJoined",
        ] {
            assert!(!encoded.contains(private));
        }
        for changed in 0..15 {
            let (account, mut scope) = sample();
            let signing = scope.signing.as_mut().unwrap();
            match changed {
                0 => signing.source_key.record_id = "a".repeat(32),
                1 => signing.source_key.revision_id = "a".repeat(32),
                2 => signing.source_key.revision_counter += 1,
                3 => signing.source_key.vault_id = "a".repeat(32),
                4 => signing.source_key.generation_id = "a".repeat(32),
                5 => signing.entitlements = json!({"unsupported":true}),
                6 => scope.target.bundle_id = "example.other".into(),
                7 => scope.target.team_id = "OTHERTEAM1".into(),
                8 => scope.target.app_id_prefix = "OTHERTEAM1".into(),
                9 => scope.target.existing_application = !scope.target.existing_application,
                10 => scope.provenance.registered_root.mode ^= 0o020,
                11 => scope.provenance.registered_root.inode += 1,
                12 => scope.provenance.registered_root.uid += 1,
                13 => scope.provenance.project_binding.canonical_root = "/other/not-opened".into(),
                _ => scope.signing = None,
            }
            let projected = profile_recovery_history(&account, &scope);
            if changed == 14 {
                assert!(projected.is_err());
            } else {
                let projected = projected.unwrap();
                assert!(projected.attempts.is_empty());
                assert_eq!(projected.hidden_unresolved, 1);
            }
        }
    }

    #[test]
    fn profile_history_retains_separate_provider_save_and_native_axes_and_joint_fences() {
        let (mut account, scope) = sample();
        for (provider, save, native, unresolved) in [
            (
                ProfileProvider::DownloadUnknown,
                ProfileSaveState::NotEntered,
                NativeSettlement::Known,
                true,
            ),
            (
                ProfileProvider::DownloadReturned,
                ProfileSaveState::Unknown,
                NativeSettlement::Known,
                true,
            ),
            (
                ProfileProvider::DownloadReturned,
                ProfileSaveState::ReadBack,
                NativeSettlement::Pending,
                true,
            ),
            (
                ProfileProvider::DownloadReturned,
                ProfileSaveState::ReadBack,
                NativeSettlement::Known,
                false,
            ),
        ] {
            let row = &mut account.profile_rows[0];
            row.update.provider = provider;
            row.update.save = save;
            row.native_settlement = native;
            let history = profile_recovery_history(&account, &scope).unwrap();
            assert_eq!(history.attempts[0].unresolved, unresolved);
            assert!(
                history.attempts[0].native_settlement == native && history.attempts[0].save == save
            );
        }
        let (other, _) = super::super::recovery_selection::tests::sample();
        let mut bundle = other.rows[0].clone();
        bundle.intent.context.operation_id = "b".repeat(32);
        bundle.intent.provenance.operation_id =
            Id::parse(&bundle.intent.context.operation_id).unwrap();
        bundle.attempt.record.context.operation_id = bundle.intent.context.operation_id.clone();
        account.rows.push(bundle);
        assert_eq!(
            profile_recovery_history(&account, &scope)
                .unwrap()
                .hidden_unresolved,
            1
        );
        account.rows[0].intent.context.operation_id =
            account.profile_rows[0].intent.context.operation_id.clone();
        account.rows[0].intent.provenance.operation_id =
            Id::parse(&account.rows[0].intent.context.operation_id).unwrap();
        account.rows[0].attempt.record.context.operation_id =
            account.rows[0].intent.context.operation_id.clone();
        assert!(profile_recovery_history(&account, &scope).is_err());
        let (mut account, scope) = sample();
        account.account = AccountRef::from_selected_issuer([99; 16]);
        assert!(profile_recovery_history(&account, &scope).is_err());
    }

    #[test]
    fn profile_history_keeps_all_thirty_two_rows_bounded_and_refuses_excess() {
        let (mut account, scope) = sample();
        let original = account.profile_rows.remove(0);
        for i in 1..=ROWS {
            let mut row = original.clone();
            row.intent.context.operation_id = format!("{i:032x}");
            row.intent.provenance.operation_id =
                Id::parse(&row.intent.context.operation_id).unwrap();
            row.intent.target.display_name = "🧪".repeat(128);
            account.profile_rows.push(row);
        }
        let history = profile_recovery_history(&account, &scope).unwrap();
        assert_eq!(history.attempts.len(), ROWS);
        assert!(bounded(&history, PROFILE_RECOVERY_LIMIT).unwrap().len() < PROFILE_RECOVERY_LIMIT);
        account.profile_rows.push(original);
        assert!(profile_recovery_history(&account, &scope).is_err());
    }
}
