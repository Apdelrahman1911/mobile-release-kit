//! Comparison/codec and actual dormant Doc methods. No native Observe, Edit,
//! Connection, admission, producer, finality or Git result is fabricated.
use super::super::{
    decode_allow, decode_commit_allow, decode_remote_allow, decode_repository_allow, requests,
    wire, Arc, DesktopBridge, DocumentBinding, MAIN,
};
use super::*;
use crate::{
    service_git_commit_protocol as commit, service_git_remote_protocol as remote,
    service_git_repository_protocol as repository, service_protocol::Id,
};
use serde_json::{json, Value};
use std::mem::size_of;

fn input(family: usize, revision: &str) -> Value {
    let mut value = json!({"projectId":"project-1", "expectedDocumentRevision":1,
        "expectedPermissionRevision":revision,"readOperationId":"git-read-1"});
    match family {
        0 => {
            value["action"] = json!("stage");
            value["paths"] = json!(["app/a"]);
            value["consentVersion"] = json!(wire::CONSENT);
        }
        1 => {
            value["message"] = json!("Reviewed commit");
            value["authorName"] = json!("Fixture");
            value["authorEmail"] = json!("fixture@example.invalid");
            value["consentVersion"] = json!(commit::CONSENT);
        }
        2 => {
            value["readOperationId"] = Value::Null;
            value["action"] = json!({"kind":"initialize"});
            value["consentVersion"] = json!(repository::CONSENT);
        }
        3 => {
            value["action"] = json!({"kind":"fetch", "expectedRevision":"a".repeat(64),
                "expectedReferenceRevision":"b".repeat(64),"remote":"origin","reference":"refs/heads/main",
                "connectionSessionId":"connection-1","expectedConnectionRevision":1});
            value["consentVersion"] = json!(remote::Kind::Fetch.consent());
        }
        _ => unreachable!(),
    }
    value
}
fn decodes(family: usize, value: &Value) -> bool {
    let raw = serde_json::to_vec(value).unwrap();
    match family {
        0 => decode_allow(&raw).is_ok(),
        1 => decode_commit_allow(&raw).is_ok(),
        2 => decode_repository_allow(&raw).is_ok(),
        3 => decode_remote_allow(&raw).is_ok(),
        _ => unreachable!(),
    }
}
fn allow(doc: &DocumentBinding, family: usize, revision: &str) -> Result<(), BridgeError> {
    let raw = serde_json::to_vec(&input(family, revision)).unwrap();
    match family {
        0 => doc
            .allow_agent_git_index(MAIN, decode_allow(&raw)?)
            .map(|_| ()),
        1 => doc
            .allow_agent_git_commit(MAIN, decode_commit_allow(&raw)?)
            .map(|_| ()),
        2 => doc
            .allow_agent_git_repository(MAIN, decode_repository_allow(&raw)?)
            .map(|_| ()),
        3 => doc
            .allow_agent_git_remote(MAIN, decode_remote_allow(&raw)?)
            .map(|_| ()),
        _ => unreachable!(),
    }
}
fn access(doc: &DocumentBinding, family: usize) -> Value {
    match family {
        0 => serde_json::to_value(doc.agent_git_index_access(MAIN).unwrap()).unwrap(),
        1 => serde_json::to_value(doc.agent_git_commit_access(MAIN).unwrap()).unwrap(),
        2 => serde_json::to_value(doc.agent_git_repository_access(MAIN).unwrap()).unwrap(),
        3 => serde_json::to_value(doc.agent_git_remote_access(MAIN).unwrap()).unwrap(),
        _ => unreachable!(),
    }
}
fn revoke(doc: &DocumentBinding, family: usize) -> Result<(), BridgeError> {
    match family {
        0 => doc.revoke_agent_git_index(MAIN).map(|_| ()),
        1 => doc.revoke_agent_git_commit(MAIN).map(|_| ()),
        2 => doc.revoke_agent_git_repository(MAIN).map(|_| ()),
        3 => doc.revoke_agent_git_remote(MAIN).map(|_| ()),
        _ => unreachable!(),
    }
}
fn dormant() -> (Arc<DesktopBridge>, DocumentBinding) {
    let bridge = Arc::new(DesktopBridge::new(
        "/inert/git-permission-never-opened".into(),
    ));
    (bridge.clone(), DocumentBinding::new(bridge))
}

#[test]
fn permission_revision_is_canonical_full_u64_not_a_js_number_or_source() {
    for n in [0, 1, (1u64 << 53) + 1, u64::MAX - 1, u64::MAX] {
        let raw = json!(n.to_string());
        let parsed: PermissionRevision = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(parsed, PermissionRevision(n));
        assert_eq!(serde_json::to_value(parsed).unwrap(), raw);
    }
    for bad in [
        json!(0),
        json!(null),
        json!(false),
        json!([]),
        json!({}),
        json!(""),
        json!("00"),
        json!("01"),
        json!("+1"),
        json!("-0"),
        json!("1e2"),
        json!(" 1"),
        json!("1 "),
        json!("1\n"),
        json!("1\r"),
        json!("1\u{2028}"),
        json!("1\u{2029}"),
        json!("18446744073709551616"),
    ] {
        assert!(serde_json::from_value::<PermissionRevision>(bad).is_err());
    }
}

#[test]
fn all_four_main_decoders_require_the_exact_checked_revision() {
    for family in 0..4 {
        for revision in ["0", "9007199254740993", "18446744073709551615"] {
            assert!(decodes(family, &input(family, revision)), "family {family}");
        }
        let good = input(family, "0");
        let mut missing = good.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("expectedPermissionRevision");
        assert!(!decodes(family, &missing));
        for bad in [
            json!(0),
            json!(null),
            json!("00"),
            json!("1\n"),
            json!("1\r"),
            json!("1\u{2028}"),
            json!("1\u{2029}"),
            json!("18446744073709551616"),
        ] {
            let mut changed = good.clone();
            changed["expectedPermissionRevision"] = bad;
            assert!(!decodes(family, &changed));
        }
        for name in ["permissionRevision", "window", "nativeReceipt", "root"] {
            let mut bad = good.clone();
            bad[name] = json!("0");
            assert!(!decodes(family, &bad));
        }
    }
}

#[test]
fn same_book_first_and_final_comparisons_consume_only_one_original_generation() {
    let mut book = Book::default();
    let original = book.permission_revision();
    let first = book.next_permission(original).unwrap();
    let competing = book.next_permission(original).unwrap();
    assert_eq!(first, competing);
    book.consume_permission(original, first).unwrap();
    // An error from an installer/projection AFTER this production commit cut
    // cannot roll the Book back. These are actual Book methods, not a lease.
    assert!(book.consume_permission(original, competing).is_err());
    assert_eq!(book.permission_revision(), PermissionRevision(1));
    let before_revoke = book.permission_revision();
    let pending = book.next_permission(before_revoke).unwrap();
    book.revoke_permission().unwrap();
    assert!(book.consume_permission(before_revoke, pending).is_err());
    assert_eq!(book.permission_revision(), PermissionRevision(2));
    book.revoke_epoch = u64::MAX;
    assert!(book.next_permission(PermissionRevision(u64::MAX)).is_err());
    assert!(book.revoke_permission().is_err());
    assert_eq!(book.permission_revision(), PermissionRevision(u64::MAX));
}

#[test]
fn every_empty_cross_family_revoke_refuses_delayed_allow_before_any_source_or_host() {
    for off_family in 0..4 {
        for delayed_family in 0..4 {
            let (bridge, doc) = dormant();
            assert_eq!(access(&doc, delayed_family)["permissionRevision"], "0");
            revoke(&doc, off_family).unwrap();
            for family in 0..4 {
                let view = access(&doc, family);
                assert_eq!(view["permissionRevision"], "1");
                assert_eq!(view["enabled"], false);
            }
            assert_eq!(
                allow(&doc, delayed_family, "0").err().unwrap().code,
                "cli_access_changed"
            );
            let state = doc.lock();
            assert!(state.git_read.is_none() && state.git_local.is_none());
            drop(state);
            assert!(doc
                .inner
                .agent_git_index
                .book
                .lock()
                .unwrap()
                .observed
                .is_none());
            assert!(doc.inner.agent_git_index.service.get().is_none());
            assert!(!bridge.application_service.status().unwrap().enabled);
        }
    }
}

#[test]
fn original_relay_loss_and_exit_invalidate_empty_permission_before_future_allow() {
    let (bridge, doc) = dormant();
    doc.git_index_relay_lost();
    assert_eq!(access(&doc, 0)["permissionRevision"], "1");
    for family in 0..4 {
        assert_eq!(
            allow(&doc, family, "0").err().unwrap().code,
            "cli_access_changed"
        );
    }
    doc.drain_git_index_for_exit();
    assert_eq!(access(&doc, 0)["permissionRevision"], "2");
    assert!(!bridge.application_service.status().unwrap().enabled);
    assert!(doc.inner.agent_git_index.service.get().is_none());
}

#[test]
fn foreign_main_access_and_exhausted_revision_do_not_reset_the_book() {
    let (bridge, doc) = dormant();
    assert!(doc.agent_git_index_access("foreign").is_err());
    assert!(doc.agent_git_commit_access("foreign").is_err());
    assert!(doc.agent_git_repository_access("foreign").is_err());
    assert!(doc.agent_git_remote_access("foreign").is_err());
    assert!(doc.revoke_agent_git_index("foreign").is_err());
    assert!(doc.revoke_agent_git_commit("foreign").is_err());
    assert!(doc.revoke_agent_git_repository("foreign").is_err());
    assert!(doc.revoke_agent_git_remote("foreign").is_err());
    assert_eq!(access(&doc, 0)["permissionRevision"], "0");
    doc.inner.agent_git_index.book.lock().unwrap().revoke_epoch = u64::MAX;
    for family in 0..4 {
        assert_eq!(
            access(&doc, family)["permissionRevision"],
            u64::MAX.to_string()
        );
        assert_eq!(
            allow(&doc, family, &u64::MAX.to_string())
                .err()
                .unwrap()
                .code,
            "cli_access_unknown"
        );
        assert!(revoke(&doc, family).is_err());
    }
    assert_eq!(access(&doc, 0)["permissionRevision"], u64::MAX.to_string());
    assert!(!bridge.application_service.status().unwrap().enabled);
}

#[test]
fn counter_overflow_or_poison_still_reaches_original_inbox_stop_and_close() {
    // The existing exclusive private StatePort fixture is the ONLY filesystem
    // effect here. No Host socket, source, runtime, Git, account or native
    // receipt is entered. A real queued Inbox row, never a native Ready row,
    // demonstrates STOP is still performed when the separate Book fails.
    use crate::application_state_store::{Fixture, PrivateStateDirectory};
    for cut in 0..8 {
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = Arc::new(super::super::ApplicationService::open(store.clone()).unwrap());
        let (_, doc) = dormant();
        assert!(doc
            .inner
            .agent_git_index
            .service
            .set(Arc::downgrade(&service))
            .is_ok());
        let scope = Arc::new(requests::NativeScope {
            project_id: Id::parse(&"a".repeat(32)).unwrap(),
            runtime_id: "project-1".into(),
            root: "/inert/no-git".into(),
            device: 1,
            inode: 2,
            registration: 1,
            document_revision: 1,
            input_revision: 1,
            read_operation_id: Some("git-read-1".into()),
            document: Arc::downgrade(&doc.inner.session_identity),
            selection: wire::Selection::new(
                wire::Action::Stage,
                "b".repeat(64),
                vec!["app/a".into()],
            )
            .unwrap()
            .into(),
            commit: None,
            changes: tokio::sync::watch::channel(0).0,
        });
        let view = service.git_index_requests().allow(scope).unwrap();
        let request = wire::Prepare {
            origin: wire::Query {
                project_id: view.project_id.unwrap(),
                service_instance: service.instance().clone(),
                request_id: Id::parse(&"c".repeat(32)).unwrap(),
            },
            grant_id: view.grant_id.unwrap(),
        };
        service.git_index_requests().prepare(request).unwrap();
        let entry = service.git_index_requests().entries().unwrap()[0].clone();
        if cut < 4 {
            doc.inner.agent_git_index.book.lock().unwrap().revoke_epoch = u64::MAX;
            assert!(revoke(&doc, cut).is_err());
        } else {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = doc.inner.agent_git_index.book.lock().unwrap();
                panic!("owned inert Git Book poison");
            }))
            .is_err());
            match cut {
                4 => assert!(revoke(&doc, 0).is_err()),
                5 => doc.git_index_relay_lost(),
                6 => doc.drain_git_index_for_exit(),
                _ => assert!(revoke(&doc, 3).is_err()),
            }
        }
        let (reason, first) = entry.stop_at().unwrap().unwrap();
        assert_eq!(
            reason,
            if cut == 6 {
                wire::Reason::Shutdown
            } else {
                wire::Reason::PermissionRevoked
            }
        );
        doc.git_index_relay_lost();
        assert_eq!(entry.stop_at().unwrap(), Some((reason, first)));
        if cut == 6 {
            assert!(service.git_index_requests().claim().is_err());
        } else {
            assert!(!service.git_index_requests().access().unwrap().enabled);
        }
        service.git_index_requests().close();
        drop(entry);
        drop(doc);
        drop(service);
        store.close().unwrap();
    }
}

#[test]
fn maximum_supported_shapes_and_four_main_wrappers_preserve_old_caps_and_cli_bytes() {
    let paths: Vec<String> = (0..64)
        .map(|i| {
            format!(
                "{i:02}/{}/{}/{}/{}",
                "a".repeat(255),
                "b".repeat(255),
                "c".repeat(255),
                "d".repeat(252)
            )
        })
        .collect();
    assert!(paths.iter().all(|p| p.len() == 1023));
    for family in 0..4 {
        let mut value = input(family, "18446744073709551615");
        value["projectId"] = json!("p".repeat(64));
        value["readOperationId"] = if family == 2 {
            Value::Null
        } else {
            json!("r".repeat(96))
        };
        value["expectedDocumentRevision"] = json!(u32::MAX - 1);
        if family == 0 {
            value["paths"] = json!(paths);
        }
        if family == 1 {
            value["message"] = json!("x".repeat(4096));
            value["authorName"] = json!("a".repeat(128));
            value["authorEmail"] = json!(format!("{}@{}", "a".repeat(127), "b".repeat(126)));
        }
        let raw = serde_json::to_vec(&value).unwrap();
        assert!(
            raw.len() + 96
                <= if family < 2 {
                    crate::git_local_protocol::REQUEST_LIMIT
                } else {
                    8192
                }
        );
        assert!(decodes(family, &value));
    }
    macro_rules! unchanged {
        ($ty:ty) => {{
            let old = <$ty>::empty();
            let raw = serde_json::to_value(&old).unwrap();
            assert_eq!(raw.as_object().unwrap().len(), 6);
            assert!(raw.get("permissionRevision").is_none());
            let mut main =
                serde_json::to_value(MainAccess::new(old, PermissionRevision(u64::MAX))).unwrap();
            assert_eq!(
                main.as_object_mut().unwrap().remove("permissionRevision"),
                Some(json!(u64::MAX.to_string()))
            );
            assert_eq!(main, raw);
            assert!(size_of::<MainAccess<$ty>>() <= size_of::<$ty>() + size_of::<u64>());
        }};
    }
    unchanged!(wire::Access);
    unchanged!(commit::Access);
    unchanged!(repository::Access);
    unchanged!(remote::Access);
    // Scalar comparisons create no owned heap. The additional fixed decimal
    // field fits the unchanged per-request envelope allowance (96 bytes).
    assert!(
        serde_json::to_vec(&json!({"expectedPermissionRevision":u64::MAX.to_string()}))
            .unwrap()
            .len()
            < 96
    );
    assert_eq!(size_of::<PermissionRevision>(), size_of::<u64>());
}
