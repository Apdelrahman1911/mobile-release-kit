use super::*;

pub(in crate::apple_provisioning_journal) fn intent(reuse: bool) -> ProfileSetupIntent {
    let old = super::super::tests::intent();
    ProfileSetupIntent {
        context: old.context,
        provenance: old.provenance,
        target: ProfileTarget {
            bundle_id: old.target.bundle_id,
            team_id: old.target.team_id,
            app_id_prefix: old.target.app_id_prefix,
            display_name: old.target.display_name,
            existing_application: true,
            entitlements_sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                .into(),
        },
        action: if reuse {
            ProfileAction::ReuseDownload
        } else {
            ProfileAction::CreateProfile
        },
        source_key: KeyReference {
            vault_id: "1".repeat(32),
            generation_id: "2".repeat(32),
            record_id: "3".repeat(32),
            revision_id: "4".repeat(32),
            revision_counter: 1,
        },
        destination: KeyReference {
            vault_id: "1".repeat(32),
            generation_id: "2".repeat(32),
            record_id: "5".repeat(32),
            revision_id: "6".repeat(32),
            revision_counter: 1,
        },
        bundle: ProfileBundle {
            resource_id: "bundle-one".into(),
            identifier: "com.example.inert".into(),
            platform: "IOS".into(),
            seed_id: "TESTTEAM01".into(),
        },
        certificate: ProfileCertificate {
            resource_id: "certificate-one".into(),
            certificate_type: "DISTRIBUTION".into(),
            not_before: "2026-10-18T10:20:30.123456+00:00".into(),
            expires_at: "2027-01-17T10:20:30.123456+00:00".into(),
            certificate_sha256: "8c9dc1f951115752a72381d233770db9be699ceffaab96440f516278093619f2"
                .into(),
            public_key_sha256: "7".repeat(64),
        },
        profile: reuse.then(|| ProfileSelection {
            resource_id: "profile-one".into(),
            name: "Synthetic existing profile".into(),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            created_at: "2026-10-18T10:20:30.123456+00:00".into(),
            expires_at: "2027-01-17T10:20:30.123456+00:00".into(),
            bundle_id_resource: "bundle-one".into(),
            certificate_resource: "certificate-one".into(),
        }),
        observed_at: old.observed_at,
        valid_until: old.valid_until,
        // Produced by actual Python ProvisioningContext/Target/Observation/
        // prepare, with cert bytes b"SYNTHETIC NOT X509" and no provider calls.
        before_sha256: if reuse {
            "a35fc9317a4eec794d7eec924e8fff040b0391112a10288cccfd259697c69caa"
        } else {
            "c94fc55ee9f01ae6e695539bc17136f5b914ff8a15a7c68e5ca0656e390a51aa"
        }
        .into(),
        plan_sha256: if reuse {
            "87989d97df81fd5eb6008eccdd7026fb4dedf67dfcf4b987c9662ba21b5de17f"
        } else {
            "a830e80e4ba389f3d28fb240cb3407c5e2119981573f5ce11990f99b944aca4e"
        }
        .into(),
        request_body_sha256: (!reuse)
            .then(|| "627f8b06752a3803b0cbde3ddb37a40ecc7e65d381f45bd24f4173a0efb5185b".into()),
    }
}
pub(in crate::apple_provisioning_journal) fn initial(intent: &ProfileSetupIntent) -> ProfileUpdate {
    ProfileUpdate {
        sequence: 1,
        provider: match intent.action {
            ProfileAction::ReuseDownload => ProfileProvider::DownloadPending,
            ProfileAction::CreateProfile => ProfileProvider::Creation(ProfileAttemptRecord {
                context: intent.context.clone(),
                plan_sha256: intent.plan_sha256.clone(),
                action: ProfileCreateAction::CreateProfile,
                status: AttemptStatus::Running,
                reason: AttemptReason::ReadbackRequired,
                possible_send: true,
                response_resource_id: None,
                response_resource_sha256: None,
                observed_resource_id: None,
                cancel_requested: false,
            }),
        },
        download: None,
        save: ProfileSaveState::NotEntered,
        saved_reference: None,
        cancel_requested: false,
    }
}
pub(in crate::apple_provisioning_journal) fn reused(intent: &ProfileSetupIntent) -> ProfileUpdate {
    let mut value = initial(intent);
    value.sequence = 2;
    value.provider = ProfileProvider::DownloadReturned;
    value.download = Some(ProfileDownload {
        profile: intent.profile.clone().unwrap(),
        bytes: 19,
        sha256: "8".repeat(64),
    });
    value
}
pub(in crate::apple_provisioning_journal) fn reseal(value: &mut ProfileSetupIntent) {
    // Synthetic DATA variants only, not a native review constructor. Bind a
    // complete one-bundle/one-cert test inventory to the altered test context.
    let b = &value.bundle;
    let c = &value.certificate;
    let profiles: Vec<_> = value
        .profile
        .iter()
        .map(|p| {
            json!([
                p.resource_id,
                p.name,
                p.uuid,
                "ACTIVE",
                p.created_at,
                p.expires_at,
                p.bundle_id_resource,
                [p.certificate_resource]
            ])
        })
        .collect();
    value.before_sha256=hash(&json!({"context":value.context.core_value(),"bundleId":value.target.bundle_id,
        "scope":"signing-resources","available":true,"reason":"observed",
        "bundles":[[b.resource_id,b.identifier,b.platform,b.seed_id]],
        "certificates":[[c.resource_id,c.certificate_type,c.expires_at,c.certificate_sha256]],"profiles":profiles})).unwrap();
    if value.action == ProfileAction::CreateProfile {
        value.request_body_sha256=Some(hash(&json!({"data":{"type":"profiles","attributes":{
            "name":value.profile_name(),"profileType":"IOS_APP_STORE"},"relationships":{
            "bundleId":{"data":{"type":"bundleIds","id":value.bundle.resource_id}},
            "certificates":{"data":[{"type":"certificates","id":value.certificate.resource_id}]}}}})).unwrap());
    }
    value.plan_sha256 = value.plan_hash().unwrap();
}

#[test]
fn profile_vectors_match_real_python_selected_resources_without_authority() {
    for reuse in [false, true] {
        let value = intent(reuse);
        value.validate().unwrap();
        initial(&value).initial(&value).unwrap();
        let mut copy = value.clone();
        reseal(&mut copy);
        assert!(copy == value);
        assert!(canonical(&value, ROW_LIMIT).unwrap().is_ascii());
        assert!(String::from_utf8(canonical(&value, ROW_LIMIT).unwrap())
            .unwrap()
            .contains("\\ud83d\\ude80"));
    }
}
#[test]
fn profile_intent_binds_full_reference_target_and_exact_plan_not_arbitrary_body() {
    for change in 0..12 {
        let mut value = intent(false);
        match change {
            0 => value.source_key.revision_id = "9".repeat(32),
            1 => value.destination.record_id = value.source_key.record_id.clone(),
            2 => value.destination.generation_id = "9".repeat(32),
            3 => value.destination.revision_counter = 2,
            4 => value.target.team_id = "OTHERTEAM1".into(),
            5 => value.certificate.certificate_sha256 = "a".repeat(64),
            6 => value.certificate.public_key_sha256 = "b".repeat(64),
            7 => value.bundle.resource_id = "other-bundle".into(),
            8 => value.valid_until = "2026-10-19T10:25:31.123456+00:00".into(),
            9 => value.request_body_sha256 = None,
            10 => value.target.entitlements_sha256 = "c".repeat(64),
            _ => value.certificate.expires_at = value.observed_at.clone(),
        }
        assert!(value.validate().is_err());
    }
    let mut encoded = serde_json::to_value(intent(false)).unwrap();
    encoded["requestBody"] = json!({"arbitrary":"not a supported field"});
    assert!(serde_json::from_value::<ProfileSetupIntent>(encoded).is_err());
}
#[test]
fn profile_nullable_fields_and_separate_action_grammars_stay_closed() {
    for field in ["profile", "requestBodySha256"] {
        let mut encoded = serde_json::to_value(intent(false)).unwrap();
        encoded.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ProfileSetupIntent>(encoded).is_err());
    }
    let value = intent(false);
    let ProfileProvider::Creation(record) = initial(&value).provider else {
        panic!()
    };
    let mut encoded = serde_json::to_value(record).unwrap();
    assert!(serde_json::from_value::<AttemptRecord>(encoded.clone()).is_err());
    encoded["action"] = json!("register_bundle_id");
    assert!(serde_json::from_value::<ProfileAttemptRecord>(encoded.clone()).is_err());
    assert!(serde_json::from_value::<AttemptRecord>(encoded).is_ok());
    let mut legacy = serde_json::to_value(super::super::tests::intent()).unwrap();
    legacy["target"]["existingApplication"] = json!(true);
    assert!(serde_json::from_value::<BundleRegistrationIntent>(legacy)
        .unwrap()
        .validate()
        .is_err());
}
#[test]
fn reuse_is_get_only_and_missing_or_changed_download_cannot_arm_save() {
    let value = intent(true);
    let first = initial(&value);
    let returned = reused(&value);
    returned.follows(&first, &value).unwrap();
    let mut armed = returned.clone();
    armed.sequence = 3;
    armed.save = ProfileSaveState::Armed;
    armed.follows(&returned, &value).unwrap();
    let mut missing = armed.clone();
    missing.download = None;
    assert!(missing.follows(&returned, &value).is_err());
    let mut changed = armed.clone();
    changed.download.as_mut().unwrap().profile.resource_id = "other".into();
    assert!(changed.follows(&returned, &value).is_err());
    let mut cancelled = armed.clone();
    cancelled.cancel_requested = true;
    assert!(cancelled.follows(&returned, &value).is_err());
    let mut creation = first.clone();
    creation.provider = initial(&intent(false)).provider;
    assert!(creation.initial(&value).is_err());
}
#[test]
fn profile_creation_preserves_existing_attempt_unknown_and_cancellation_rules() {
    let value = intent(false);
    let first = initial(&value);
    let mut lost = first.clone();
    lost.sequence = 2;
    let ProfileProvider::Creation(record) = &mut lost.provider else {
        panic!()
    };
    record.status = AttemptStatus::Unknown;
    record.reason = AttemptReason::ProviderOutcomeUnknown;
    lost.follows(&first, &value).unwrap();
    let mut cancelled = lost.clone();
    cancelled.sequence = 3;
    cancelled.cancel_requested = true;
    let ProfileProvider::Creation(record) = &mut cancelled.provider else {
        panic!()
    };
    record.status = AttemptStatus::CancellationRequested;
    record.cancel_requested = true;
    cancelled.follows(&lost, &value).unwrap();
    let mut laundered = cancelled.clone();
    laundered.sequence = 4;
    let ProfileProvider::Creation(record) = &mut laundered.provider else {
        panic!()
    };
    record.status = AttemptStatus::Cancelled;
    record.reason = AttemptReason::CancelledBeforeSend;
    record.possible_send = false;
    assert!(laundered.follows(&cancelled, &value).is_err());
    let mut replay = first.clone();
    replay.sequence = 4;
    assert!(replay.follows(&cancelled, &value).is_err());
}
#[test]
fn sparse_post_receipt_does_not_count_as_a_download_or_save_arm() {
    let value = intent(false);
    let first = initial(&value);
    let mut response = first.clone();
    response.sequence = 2;
    let ProfileProvider::Creation(record) = &mut response.provider else {
        panic!()
    };
    record.status = AttemptStatus::RecoveryRequired;
    record.reason = AttemptReason::ReadbackRequired;
    record.response_resource_id = Some("created-profile".into());
    record.response_resource_sha256 = Some("9".repeat(64));
    response.follows(&first, &value).unwrap();
    let mut invalid = response.clone();
    invalid.sequence = 3;
    invalid.save = ProfileSaveState::Armed;
    assert!(invalid.follows(&response, &value).is_err());
    let mut restored = first.clone();
    restored.sequence = 3;
    assert!(restored.follows(&response, &value).is_err());
}
#[test]
fn save_unknown_and_exact_destination_are_independent_absorbing_fences() {
    let value = intent(true);
    let returned = reused(&value);
    let mut armed = returned.clone();
    armed.sequence = 3;
    armed.save = ProfileSaveState::Armed;
    armed.follows(&returned, &value).unwrap();
    let mut saved = armed.clone();
    saved.sequence = 4;
    saved.save = ProfileSaveState::ReadBack;
    saved.saved_reference = Some(value.destination.clone());
    saved.follows(&armed, &value).unwrap();
    let mut other = saved.clone();
    other.saved_reference.as_mut().unwrap().revision_id = "a".repeat(32);
    assert!(other.follows(&armed, &value).is_err());
    let mut lost = armed.clone();
    lost.sequence = 4;
    lost.save = ProfileSaveState::Unknown;
    lost.follows(&armed, &value).unwrap();
    let row = ProfileSetupRow {
        intent: value.clone(),
        send_armed: false,
        update: lost.clone(),
        native_settlement: NativeSettlement::Known,
    };
    row.validate().unwrap();
    assert!(row.unresolved());
    saved.sequence = 5;
    assert!(saved.follows(&lost, &value).is_err());
    let mut reset = lost.clone();
    reset.sequence = 5;
    reset.save = ProfileSaveState::NotEntered;
    assert!(reset.follows(&lost, &value).is_err());
    let mut row = row;
    row.update = saved;
    assert!(!row.unresolved()); // DATA rule, no native proof minted.
    row.native_settlement = NativeSettlement::Pending;
    assert!(row.unresolved());
}
