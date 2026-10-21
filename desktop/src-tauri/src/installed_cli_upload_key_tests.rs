//! Real installed collector/codec/output, inert bounded IDs only. No socket,
//! service startup, native admission, private input or key operation is run.
use super::*;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn origin() -> key::Query {
    key::Query {
        project_id: id('a'),
        service_instance: id('b'),
        request_id: id('c'),
    }
}
fn response(body: p::ResponseBody) -> p::Response {
    p::Response {
        version: p::VERSION,
        request_id: id('d'),
        service_instance: id('b'),
        client_id: id('e'),
        session_id: id('f'),
        response: body,
    }
}
fn row() -> key::Status {
    key::Status {
        schema_version: 1,
        origin: origin(),
        grant_id: id('d'),
        kind: key::Kind::GenerateNew,
        state: key::State::Queued,
        settlement: p::Settlement::Pending,
        reason: key::Reason::None,
        asset_operation_id: None,
        key: None,
        do_not_replay: true,
    }
}
fn reference() -> key::KeyReference {
    key::KeyReference {
        vault_id: id('1'),
        generation_id: id('2'),
        record_id: id('3'),
        revision_id: id('4'),
        revision_counter: 1,
    }
}

#[test]
fn backup_and_restore_output_keep_delivery_new_reference_and_assignment_distinct() {
    for (kind, state, saved, expected) in [
        (key::Kind::BackupEncrypted, key::State::BackupDelivered, None, "two native dialogs"),
        (key::Kind::RestoreEncrypted, key::State::RestoredUnassigned, Some(reference()), "NEW, unassigned"),
    ] {
        let mut value = row();
        value.kind = kind; value.state = state; value.key = saved; value.settlement = p::Settlement::Settled;
        value.asset_operation_id = Some(7);
        let result = response(p::ResponseBody::UploadKeyRequest(value.clone()));
        let (code, bytes) = output(&result, &origin(), Some(&id('d')), false).unwrap();
        assert_eq!(code, 0);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(expected));
        assert!(text.contains("No assignment, replacement"));
        assert!(!text.contains("No backup, restore"));
        let (_, json) = output(&result, &origin(), Some(&id('d')), true).unwrap();
        let encoded = String::from_utf8(json).unwrap();
        for forbidden in ["backupPath", "recoveryCode", "password", "privateKey", "destinationPath"] {
            assert!(!encoded.contains(forbidden));
        }
        let mut wrong = value;
        wrong.kind = key::Kind::BindReviewed;
        assert!(output(&response(p::ResponseBody::UploadKeyRequest(wrong)), &origin(), None, false).is_err());
    }
}

#[test]
fn backup_cli_still_accepts_only_ids_not_a_file_pair_or_restore_override() {
    for option in ["--backup-path", "--password", "--recovery-code", "--restore", "--auto-bind", "--replace"] {
        let args: Vec<OsString> = [COMMANDS[1], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "dddddddddddddddddddddddddddddddd", "--reviewed", option].into_iter().map(OsString::from).collect();
        assert!(parse(&args).is_err());
    }
    let mut value = row();
    value.kind = key::Kind::RestoreEncrypted; value.state = key::State::RecoveryRequired;
    value.settlement = p::Settlement::Unknown; value.reason = key::Reason::RecoveryRequired;
    let (code, bytes) = output(&response(p::ResponseBody::UploadKeyRequest(value)), &origin(), None, false).unwrap();
    assert_eq!(code, 6);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("may have left files or a NEW record"));
    assert!(!text.contains("key restored as a NEW"));
}

#[test]
fn actual_collector_admits_only_four_ids_only_commands_and_explicit_submit_review() {
    let q = origin();
    let g = id('d');
    for words in [
        vec![COMMANDS[0], q.project_id.as_str()],
        vec![
            COMMANDS[1],
            q.project_id.as_str(),
            q.service_instance.as_str(),
            g.as_str(),
            "--reviewed",
        ],
        vec![
            COMMANDS[2],
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
        vec![
            COMMANDS[3],
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
    ] {
        for json in [false, true] {
            let args = super::super::collect_arguments(
                words
                    .iter()
                    .copied()
                    .chain(json.then_some("--json"))
                    .map(OsString::from),
            );
            assert!(recognizes(&args));
            assert_eq!(parse(&args).unwrap().json, json);
            for extra in [
                "--replace",
                "--password",
                "--backup",
                "/inert/private/file",
                "--remember",
                "--retry",
            ] {
                let mut bad = args.clone();
                bad.push(extra.into());
                assert!(parse(&bad).is_err());
            }
        }
    }
    assert!(parse(
        &[
            COMMANDS[1],
            q.project_id.as_str(),
            q.service_instance.as_str(),
            g.as_str()
        ]
        .map(OsString::from)
    )
    .is_err());
    assert!(parse(&[COMMANDS[0], "not-a-service-id"].map(OsString::from)).is_err());
    assert!(parse(&super::super::collect_arguments(std::iter::repeat_n(
        OsString::from("x"),
        20
    )))
    .is_err());
}
#[test]
fn submit_wire_carries_only_original_ids_and_cannot_request_material_or_a_new_action() {
    let request = p::Request {
        version: p::VERSION,
        request_id: id('f'),
        request: p::RequestBody::UploadKeySubmit(key::Submit {
            origin: origin(),
            grant_id: id('d'),
        }),
    };
    let bytes = p::encode_request(&request).unwrap();
    assert!(bytes.len() < key::RAW_LIMIT);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["request"]["method"], "upload-key.submit");
    for field in [
        "kind",
        "declaration",
        "previewToken",
        "password",
        "fields",
        "path",
        "recordId",
        "window",
        "command",
    ] {
        value["request"]["params"][field] = "refused".into();
        assert!(p::decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
        value["request"]["params"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
}
#[test]
fn pending_saved_unassigned_and_reviewed_bind_are_distinct_and_exactly_correlated() {
    let mut r = row();
    let q = origin();
    let (_, bytes) = output(
        &response(p::ResponseBody::UploadKeyRequest(r.clone())),
        &q,
        Some(&id('d')),
        false,
    )
    .unwrap();
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains("No saved or assigned success"));
    for (kind, state, text) in [
        (
            key::Kind::GenerateNew,
            key::State::SavedUnassigned,
            "saved, not assigned",
        ),
        (
            key::Kind::BindReviewed,
            key::State::Assigned,
            "assigned in this Desktop session",
        ),
    ] {
        r.kind = kind;
        r.state = state;
        r.settlement = p::Settlement::Settled;
        r.asset_operation_id = Some(7);
        r.key = Some(reference());
        let view = response(p::ResponseBody::UploadKeyRequest(r.clone()));
        let (code, bytes) = output(&view, &q, Some(&id('d')), false).unwrap();
        assert_eq!(code, 0);
        assert!(String::from_utf8(bytes).unwrap().contains(text));
        assert!(output(&view, &q, Some(&id('9')), false).is_err());
        let mut other = q.clone();
        other.project_id = id('9');
        assert!(output(&view, &other, None, false).is_err());
        let mut wrong = r.clone();
        wrong.kind = if kind == key::Kind::GenerateNew {
            key::Kind::BindReviewed
        } else {
            key::Kind::GenerateNew
        };
        assert!(output(
            &response(p::ResponseBody::UploadKeyRequest(wrong)),
            &q,
            None,
            false
        )
        .is_err());
        let mut missing = r.clone();
        missing.key = None;
        assert!(missing.validate().is_err());
    }
    r.reason = key::Reason::PermissionRevoked;
    assert!(r.validate().is_err()); // Late stop is not successful assignment.
}
#[test]
fn unknown_or_lost_ack_prints_only_original_status_stop_and_never_a_replay_command() {
    let q = origin();
    let mut r = row();
    r.state = key::State::Unknown;
    r.settlement = p::Settlement::Unknown;
    r.reason = key::Reason::CleanupUnknown;
    let (code, bytes) = output(
        &response(p::ResponseBody::UploadKeyRequest(r)),
        &q,
        None,
        false,
    )
    .unwrap();
    assert_eq!(code, 6);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains(COMMANDS[2]) && text.contains(COMMANDS[3]));
    assert!(!text.contains(COMMANDS[1]));
    for json in [false, true] {
        let lost = String::from_utf8(unconfirmed(&q, Error::StateUnknown, json)).unwrap();
        assert!(lost.contains(q.request_id.as_str()));
        assert!(!lost.contains(COMMANDS[1]));
        if json {
            let v: serde_json::Value = serde_json::from_str(&lost).unwrap();
            assert_eq!(v["doNotReplay"], true);
        }
    }
    let wrong = response(p::ResponseBody::UploadKeyAccess(key::Access::empty()));
    assert!(output(&wrong, &q, None, true).is_err());
}
#[test]
fn scope_and_existing_request_catalogue_expose_only_bounded_original_addresses() {
    let q = origin();
    let empty = response(p::ResponseBody::UploadKeyAccess(key::Access::empty()));
    assert!(
        String::from_utf8(scope_output(&empty, &q.project_id, false).unwrap().1)
            .unwrap()
            .contains("No upload-key consent")
    );
    let a = key::Access {
        schema_version: 1,
        service_instance: Some(id('b')),
        project_id: Some(id('a')),
        grant_id: Some(id('d')),
        kind: Some(key::Kind::BindReviewed),
        request_id: Some(id('c')),
        enabled: false,
        remaining_ms: 0,
        consumed: true,
    };
    assert!(scope_output(
        &response(p::ResponseBody::UploadKeyAccess(a.clone())),
        &id('9'),
        false
    )
    .is_err());
    let bytes = scope_output(
        &response(p::ResponseBody::UploadKeyAccess(a)),
        &q.project_id,
        true,
    )
    .unwrap()
    .1;
    assert!(bytes.len() < key::VIEW_LIMIT);
    let mut catalogue = crate::service_request_catalogue::Catalogue {
        schema_version: 2,
        scope: crate::service_request_catalogue::Scope::CurrentHostRetainedRequests,
        sampling: crate::service_request_catalogue::Sampling::PerRequestNotAtomic,
        service_instance: id('b'),
        project_id: id('a'),
        do_not_replay: true,
        requests: vec![],
        additional_requests: Some(vec![]),
    };
    for n in 1..=key::REQUEST_LIMIT {
        catalogue.additional_requests.as_mut().unwrap().push(
            crate::service_request_catalogue::AdditionalRequest {
                family: crate::service_request_catalogue::AdditionalFamily::AndroidUploadKey,
                request_id: Id::parse(&format!("{n:032x}")).unwrap(),
            },
        );
    }
    catalogue.validate().unwrap();
    assert!(crate::service_request_catalogue::human(&catalogue).contains(COMMANDS[2]));
    let copy = catalogue.additional_requests.as_ref().unwrap()[0].clone();
    catalogue.additional_requests.as_mut().unwrap().push(copy);
    assert!(catalogue.validate().is_err());
}
