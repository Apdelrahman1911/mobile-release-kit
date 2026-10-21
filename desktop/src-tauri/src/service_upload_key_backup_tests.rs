//! Same existing Inbox/Entry/Claim fixture and bounded callback DATA. These
//! tests do not construct native picker facts, vault keys, storage or receipts.
use super::*;

fn outcome(kind: p::Kind) -> (p::State, Option<p::KeyReference>) {
    match kind {
        p::Kind::BackupEncrypted => (p::State::BackupDelivered, None),
        p::Kind::RestoreEncrypted => (p::State::RestoredUnassigned, Some(key())),
        _ => panic!("fixed backup test kind"),
    }
}

#[test]
fn backup_selections_are_distinct_closed_consents_without_file_or_password_inputs() {
    let values = [
        serde_json::json!({"kind":"backup-encrypted","recordId":id(5),"expectedRevision":1}),
        serde_json::json!({"kind":"restore-encrypted","declaration":p::RESTORE_DECLARATION}),
    ];
    for (n, value) in values.iter().enumerate() {
        let parsed: p::Selection = serde_json::from_value(value.clone()).unwrap();
        assert!(parsed.valid());
        assert_eq!(
            parsed.kind(),
            [p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted][n]
        );
        assert_eq!(
            parsed.kind().consent(),
            [
                "agent-android-upload-key-backup-once-v1",
                "agent-android-upload-key-restore-once-v1"
            ][n]
        );
        assert_ne!(parsed.kind().consent(), p::Kind::GenerateNew.consent());
        assert_ne!(parsed.kind().consent(), p::Kind::BindReviewed.consent());
        assert!(serde_json::to_vec(&parsed).unwrap().len() + 96 < p::RAW_LIMIT);
        for field in [
            "path",
            "backupPath",
            "recoveryCode",
            "password",
            "fields",
            "replace",
            "autoBind",
            "kindOverride",
        ] {
            let mut extra = value.clone();
            extra[field] = serde_json::json!("never-sent");
            assert!(serde_json::from_value::<p::Selection>(extra).is_err());
        }
    }
    for value in [
        serde_json::json!({"kind":"restore-encrypted"}),
        serde_json::json!({"kind":"restore-encrypted","declaration":p::DECLARATION}),
        serde_json::json!({"kind":"backup-encrypted","recordId":id(5),"expectedRevision":0}),
        serde_json::json!({"kind":"backup-encrypted","recordId":id(5),"expectedRevision":4294967296u64}),
    ] {
        assert!(serde_json::from_value::<p::Selection>(value).map_or(true, |s| !s.valid()));
    }
    // Old consent and serialization are not upgraded by adding new kinds.
    assert_eq!(
        serde_json::to_string(&p::Selection::GenerateNew {
            declaration: p::DECLARATION.into()
        })
        .unwrap(),
        "{\"kind\":\"generate-new\",\"declaration\":\"new-application-no-existing-upload-key\"}"
    );
    assert_eq!(
        p::Kind::BindReviewed.consent(),
        "agent-android-upload-key-bind-once-v1"
    );
}

#[test]
fn delivery_and_restored_reference_cannot_cross_kind_or_settlement() {
    for kind in [p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
        let r = Rig::new(kind);
        r.allow();
        let mut s = r.inbox.submit(r.input.clone()).unwrap();
        let (state, key) = outcome(kind);
        s.state = state;
        s.key = key;
        s.asset_operation_id = Some(7);
        s.settlement = Settlement::Settled;
        s.validate().unwrap();
        assert!(serde_json::to_vec(&s).unwrap().len() < p::VIEW_LIMIT);
        for other in [
            p::Kind::GenerateNew,
            p::Kind::BindReviewed,
            if kind == p::Kind::BackupEncrypted {
                p::Kind::RestoreEncrypted
            } else {
                p::Kind::BackupEncrypted
            },
        ] {
            let mut wrong = s.clone();
            wrong.kind = other;
            assert!(wrong.validate().is_err());
        }
        let mut wrong = s.clone();
        wrong.key = if s.key.is_some() {
            None
        } else {
            Some(super::key())
        };
        assert!(wrong.validate().is_err());
        if kind == p::Kind::RestoreEncrypted {
            let mut reused_counter = s.clone();
            reused_counter.key.as_mut().unwrap().revision_counter = 2;
            assert!(reused_counter.validate().is_err()); // NEW, never replace/revision reuse.
        }
        let mut pending = s.clone();
        pending.settlement = Settlement::Pending;
        assert!(pending.validate().is_err());
        let mut stopped = s;
        stopped.reason = p::Reason::Expired;
        assert!(stopped.validate().is_err());
    }
}

#[test]
fn both_backup_kinds_keep_the_same_three_original_return_barriers_in_all_orders() {
    for kind in [p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let r = Rig::new(kind);
            let (claim, link) = r.claim();
            arm(&link);
            let mut claim = Some(claim);
            let (state, key) = outcome(kind);
            for (position, part) in order.into_iter().enumerate() {
                match part {
                    0 => claim.take().unwrap().returned(Ok(())),
                    1 => link
                        .entry()
                        .native_retired(7, state, p::Reason::None, key.clone()),
                    _ => link.entry().continuation_joined(true),
                }
                let actual = r.status();
                if position < 2 {
                    assert_eq!(actual.settlement, Settlement::Pending);
                    assert!(!actual.state.success());
                    assert!(actual.key.is_none());
                } else {
                    assert_eq!((actual.state, actual.key), (state, key.clone()));
                }
            }
            assert!(r.inbox.claim().unwrap().is_none());
            assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), r.status());
        }
    }
}

#[test]
fn lost_caller_or_continuation_and_wrong_native_kind_are_absorbing_unknown() {
    for kind in [p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
        for missing in 0..3 {
            let r = Rig::new(kind);
            let (claim, link) = r.claim();
            arm(&link);
            let (state, key) = outcome(kind);
            if missing == 0 {
                drop(claim);
            } else {
                claim.returned(Ok(()));
            }
            if missing == 1 {
                link.entry().native_retired(
                    7,
                    p::State::Assigned,
                    p::Reason::None,
                    Some(super::key()),
                );
            } else {
                link.entry().native_retired(7, state, p::Reason::None, key);
            }
            link.entry().continuation_joined(missing != 2);
            let actual = r.status();
            assert_eq!(actual.state, p::State::Unknown);
            assert!(actual.key.is_none());
            assert!(r.inbox.claim().unwrap().is_none());
            assert_eq!(
                r.inbox.submit(r.input.clone()).unwrap().state,
                p::State::Unknown
            );
        }
    }
}

#[test]
fn late_original_stop_suppresses_delivery_and_new_reference_without_replaying() {
    for kind in [p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
        let r = Rig::new(kind);
        let (claim, link) = r.claim();
        arm(&link);
        let (state, key) = outcome(kind);
        claim.returned(Ok(()));
        link.entry().native_retired(7, state, p::Reason::None, key);
        r.inbox.revoke(&r.input.grant_id, Instant::now()).unwrap();
        r.status(); // The same original's actual stop is observed, not a new clock.
        link.entry().continuation_joined(true);
        let actual = r.status();
        assert_eq!(actual.state, p::State::Cancelled);
        assert_eq!(actual.settlement, Settlement::Settled);
        assert!(actual.key.is_none());
        assert!(actual.do_not_replay);
        assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), actual);
    }
}
