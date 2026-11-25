use super::*;

pub(in crate::apple_provisioning_journal) fn intent() -> BundleRegistrationIntent {
    let account = AccountRef::from_selected_issuer([1; 16]);
    BundleRegistrationIntent {
        context: ProvisioningContext {
            project_id: "project-1".into(),
            client_id: "native-test-client".into(),
            operation_id: "1".repeat(32),
            observation_revision: 1,
            account_ref: account,
            credential_record_id: "record-1".into(),
            credential_revision: 1,
            credential_context_revision: 1,
        },
        provenance: NativeProvenance {
            project_binding: ProjectBinding {
                project_id: Id::parse(&"2".repeat(32)).unwrap(),
                canonical_root: "/synthetic/reference-only".into(),
                device: 202,
                inode: 101,
            },
            operation_id: Id::parse(&"1".repeat(32)).unwrap(),
            owner_generation: Id::parse(&"5".repeat(32)).unwrap(),
            registration_generation: 1,
            registered_root: RegisteredRootData {
                path: "/synthetic/reference-only".into(),
                device: 202,
                inode: 101,
                mode: 0o40755,
                uid: 501,
                gid: 20,
            },
            draft_revision: 1,
            baseline_generation: 1,
            saved_config: Content {
                bytes: 123,
                sha256: "3".repeat(64),
            },
            saved_version: SavedVersion {
                source: "version.properties".into(),
                bytes: 45,
                sha256: "4".repeat(64),
                name: "1.2.3".into(),
                build: 7,
            },
        },
        target: BundleTarget {
            bundle_id: "com.example.inert".into(),
            team_id: "TESTTEAM01".into(),
            app_id_prefix: "TESTTEAM01".into(),
            display_name: "Synthetic 🚀".into(),
            existing_application: false,
        },
        observed_at: "2026-10-19T10:20:30.123456+00:00".into(),
        valid_until: "2026-10-19T10:25:30.123456+00:00".into(),
        // Cross-language vector synthesized with the actual, credential-free
        // Python ProvisioningContext/Target/Observation/prepare_bundle helper.
        before_sha256: "0a2ff738fffffbd3a9a4d1a63242e391ada9ba1ed1b295e1a0f044839b64ecfd".into(),
        plan_sha256: "fad26468c5361e0fcb49f18c97fb1910f6ca494d65da7f44a8676fa025ae537f".into(),
        request_body_sha256: "459a26665c038c87bd279e000e2b70de31976942ce1b496726b0b632904c3aed"
            .into(),
    }
}

pub(in crate::apple_provisioning_journal) fn reseal_fixture(intent: &mut BundleRegistrationIntent) {
    // Only synthetic DATA variants for state-transition/CAS cases below, not a
    // native plan/consent constructor. The fixed Python vector above is separate.
    let before = json!({"context":intent.context.core_value(),"bundleId":intent.target.bundle_id,
        "scope":"bundle-identifiers","available":true,"reason":"observed",
        "bundles":[],"certificates":[],"profiles":[]});
    intent.before_sha256 = hash(&before).unwrap();
    intent.request_body_sha256 = hash(&intent.target.request_body()).unwrap();
    intent.plan_sha256 = hash(
        &json!({"context":intent.context.core_value(),"target":intent.target.core_value(),
        "observation":intent.before_sha256,"validUntil":intent.valid_until,
        "action":"register_bundle_id","reason":"new_application_registration_requires_approval",
        "request":{"kind":"register_bundle_id","method":"POST","path":"/v1/bundleIds",
            "query":[],"bodySha256":intent.request_body_sha256},
        "binding":null,"selection":{"bundle":null,"certificate":null,"profile":null},"csr":null}),
    )
    .unwrap();
}

pub(in crate::apple_provisioning_journal) fn armed(
    intent: &BundleRegistrationIntent,
) -> AttemptUpdate {
    AttemptUpdate {
        sequence: 1,
        record: AttemptRecord {
            context: intent.context.clone(),
            plan_sha256: intent.plan_sha256.clone(),
            action: Action::RegisterBundleId,
            status: AttemptStatus::Running,
            reason: AttemptReason::ReadbackRequired,
            possible_send: true,
            response_resource_id: None,
            response_resource_sha256: None,
            observed_resource_id: None,
            cancel_requested: false,
        },
    }
}

pub(in crate::apple_provisioning_journal) fn unknown(
    intent: &BundleRegistrationIntent,
) -> AttemptUpdate {
    let mut value = armed(intent);
    value.sequence = 2;
    value.record.status = AttemptStatus::Unknown;
    value.record.reason = AttemptReason::ProviderOutcomeUnknown;
    value
}

#[test]
fn fixed_bundle_plan_matches_actual_python_ascii_hash_vector() {
    let intent = intent();
    assert_eq!(
        intent.context.account_ref.as_str(),
        "0fce421a5585f47c5eecb0e79e66ab8eac29812975af82ea7701db7981a9a251"
    );
    intent.validate().unwrap();
    let bytes = canonical(&intent, ROW_LIMIT).unwrap();
    assert!(bytes.is_ascii());
    assert!(String::from_utf8(bytes).unwrap().contains("\\ud83d\\ude80"));
    assert_ne!(
        intent.context.project_id,
        intent.provenance.project_binding.project_id.as_str()
    );
}

#[test]
fn intent_rejects_other_plan_body_continuity_and_native_source_substitutions() {
    for change in 0..8 {
        let mut value = intent();
        match change {
            0 => value.target.existing_application = true,
            1 => value.target.app_id_prefix = "OTHERTEAM1".into(),
            2 => value.target.bundle_id.push_str(".changed"),
            3 => value.request_body_sha256 = "0".repeat(64),
            4 => value.provenance.registered_root.inode += 1,
            5 => value.provenance.operation_id = Id::parse(&"a".repeat(32)).unwrap(),
            6 => value.provenance.saved_version.source = "../version.properties".into(),
            _ => value.target.display_name = "x".repeat(129),
        }
        assert!(value.validate().is_err());
    }
    let mut value = serde_json::to_value(intent()).unwrap();
    value["target"]["entitlementsJson"] = json!("not an extensible blob");
    assert!(serde_json::from_value::<BundleRegistrationIntent>(value).is_err());
}

#[test]
fn timestamps_are_canonical_calendar_data_and_exact_five_minute_interval() {
    assert!(utc_micros("2024-02-29T23:59:59+00:00").is_some());
    for value in [
        "2023-02-29T10:20:30+00:00",
        "2026-00-19T10:20:30+00:00",
        "2026-10-19T24:00:00+00:00",
        "2026-10-19T10:20:30Z",
        "2026-10-19T10:20:30+01:00",
        "2026-10-19T10:20:30.000000+00:00",
        "2026-10-19T10:20:30.1+00:00",
    ] {
        assert!(utc_micros(value).is_none());
    }
    let mut value = intent();
    value.valid_until = "2026-10-19T10:25:31.123456+00:00".into();
    reseal_fixture(&mut value);
    assert!(value.validate().is_err());
}

#[test]
fn attempt_nullable_members_and_closed_action_reason_are_required() {
    let value = armed(&intent()).record;
    for field in [
        "responseResourceId",
        "responseResourceSha256",
        "observedResourceId",
    ] {
        let mut json = serde_json::to_value(&value).unwrap();
        json.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<AttemptRecord>(json).is_err());
    }
    for (field, replacement) in [
        ("action", "create_certificate"),
        ("reason", "unbounded_provider_error"),
        ("status", "prepared"),
    ] {
        let mut json = serde_json::to_value(&value).unwrap();
        json[field] = replacement.into();
        assert!(serde_json::from_value::<AttemptRecord>(json).is_err());
    }
}

#[test]
fn attempts_preserve_armed_uncertainty_and_cancellation_without_false_no_send() {
    let intent = intent();
    let first = armed(&intent);
    first.armed(&intent).unwrap();
    let lost = unknown(&intent);
    lost.follows(&first, &intent).unwrap();
    let mut next = lost.clone();
    next.sequence = 3;
    next.record.status = AttemptStatus::Cancelled;
    next.record.reason = AttemptReason::CancelledBeforeSend;
    next.record.possible_send = false;
    next.record.cancel_requested = true;
    assert!(next.follows(&lost, &intent).is_err());
    let mut cancelled = first.clone();
    cancelled.sequence = 2;
    cancelled.record.status = AttemptStatus::CancellationRequested;
    cancelled.record.cancel_requested = true;
    cancelled.follows(&first, &intent).unwrap();
    next.follows(&cancelled, &intent).unwrap();
    next.record.cancel_requested = false;
    assert!(next.follows(&cancelled, &intent).is_err());
    let mut replay = first.clone();
    replay.sequence = 3;
    assert!(replay.follows(&lost, &intent).is_err());

    // Follow the actual Python request_cancel shape after an unknown send:
    // status/cancel change, but original reason and all send facts survive.
    let mut unknown_cancel = lost.clone();
    unknown_cancel.sequence = 3;
    unknown_cancel.record.status = AttemptStatus::CancellationRequested;
    unknown_cancel.record.cancel_requested = true;
    unknown_cancel.follows(&lost, &intent).unwrap();
    let mut reset = unknown_cancel.clone();
    reset.record.reason = AttemptReason::ReadbackRequired;
    assert!(reset.follows(&lost, &intent).is_err());
    for (status, reason, possible_send) in [
        (
            AttemptStatus::Cancelled,
            AttemptReason::CancelledBeforeSend,
            false,
        ),
        (
            AttemptStatus::Cancelled,
            AttemptReason::ProviderRejectedRequest,
            true,
        ),
    ] {
        let mut false_refusal = unknown_cancel.clone();
        false_refusal.sequence = 4;
        false_refusal.record.status = status;
        false_refusal.record.reason = reason;
        false_refusal.record.possible_send = possible_send;
        assert!(false_refusal.follows(&unknown_cancel, &intent).is_err());
    }
    for previous in [&lost, &unknown_cancel] {
        let mut recovery_reset = previous.clone();
        recovery_reset.sequence += 1;
        recovery_reset.record.status = AttemptStatus::RecoveryRequired;
        recovery_reset.record.reason = AttemptReason::ReadbackRequired;
        assert!(recovery_reset.follows(previous, &intent).is_err());
        recovery_reset.record.response_resource_id = Some("invented-response".into());
        recovery_reset.record.response_resource_sha256 = Some("6".repeat(64));
        assert!(recovery_reset.follows(previous, &intent).is_err());
    }
}

#[test]
fn original_response_ids_are_monotonic_and_terminal_does_not_restart() {
    let intent = intent();
    let first = armed(&intent);
    let mut response = first.clone();
    response.sequence = 2;
    response.record.status = AttemptStatus::RecoveryRequired;
    response.record.response_resource_id = Some("synthetic-resource".into());
    response.record.response_resource_sha256 = Some("6".repeat(64));
    response.follows(&first, &intent).unwrap();
    let mut done = response.clone();
    done.sequence = 3;
    done.record.status = AttemptStatus::Succeeded;
    done.record.reason = AttemptReason::ProviderResourceConfirmed;
    done.record.observed_resource_id = done.record.response_resource_id.clone();
    done.follows(&response, &intent).unwrap();
    let mut changed = done.clone();
    changed.record.response_resource_id = Some("another-resource".into());
    changed.record.observed_resource_id = changed.record.response_resource_id.clone();
    assert!(changed.follows(&response, &intent).is_err());
    let mut again = unknown(&intent);
    again.sequence = 4;
    assert!(again.follows(&done, &intent).is_err());
    let mut invented_after_unknown = response.clone();
    invented_after_unknown.sequence = 3;
    assert!(invented_after_unknown
        .follows(&unknown(&intent), &intent)
        .is_err());
}

#[test]
fn terminal_child_data_never_erases_account_pending_or_unknown_native_axis() {
    let intent = intent();
    let mut failed = armed(&intent);
    failed.sequence = 2;
    failed.record.status = AttemptStatus::Failed;
    failed.record.reason = AttemptReason::AuthorizationChanged;
    failed.record.possible_send = false;
    let mut row = JournalRow {
        intent,
        send_armed: true,
        attempt: failed,
        native_settlement: NativeSettlement::Pending,
    };
    row.validate().unwrap();
    assert!(row.unresolved());
    row.native_settlement = NativeSettlement::Unknown;
    assert!(row.unresolved());
    // DATA classifier only; no native witness is created by this test.
    row.native_settlement = NativeSettlement::Known;
    assert!(!row.unresolved());
    row.attempt = unknown(&row.intent);
    assert!(row.unresolved());
    row.send_armed = false;
    assert!(row.validate().is_err());
}
