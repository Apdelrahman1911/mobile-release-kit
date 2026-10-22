//! Existing comparison/Connection/Inbox fixtures only. No native source, token,
//! provider, Supervisor task, filesystem or installed permission is entered.
use super::*;
use crate::service_protocol::{Error, Id};
use serde_json::{json, Value};

const ORDINARY: &str = r#"{"kind":"setup-prepare","sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":12,"base":"release/setup"}"#;

fn input() -> d::Input {
    serde_json::from_str::<d::Selection>(ORDINARY)
        .unwrap()
        .input()
        .unwrap()
}
fn reference() -> wire::Review {
    let mut original = input();
    if let d::Input::SetupPrepare(v) = &mut original {
        v.session_id = "github-session-1".into();
    }
    wire::Review::SetupPrepare(wire::dispatch::RequestReference {
        session_id: "github-session-1".into(),
        expected_revision: 1,
        request_sha256: original.hash().unwrap(),
    })
}
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn entry(at: Instant) -> (Arc<()>, request::Inbox, request::Claim, Arc<request::Entry>) {
    // Same small in-memory Book/ReadPermission fixture as the original dispatch
    // tests. These explicit return transitions are DATA, not native receipts.
    let doc = Arc::new(());
    let scope = request::NativeScope::new(
        id(1),
        "project-1".into(),
        "/never-opened-ordinary-setup".into(),
        1,
        2,
        3,
        reference(),
        Arc::new(()),
        at + Duration::from_secs(60),
        Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                at + Duration::from_secs(80),
            ),
        ),
        Arc::downgrade(&doc),
        tokio::sync::watch::channel(1).0,
    );
    let inbox = request::Inbox::new(id(2));
    inbox.allow(scope, id(3)).unwrap();
    inbox
        .submit(wire::Submit {
            origin: wire::Query {
                project_id: id(1),
                service_instance: id(2),
                request_id: id(4),
            },
            grant_id: id(3),
        })
        .unwrap();
    let call = inbox.claim().unwrap().unwrap();
    let original = call.entry().clone();
    (doc, inbox, call, original)
}
fn compact() -> wire::dispatch::Snapshot {
    use wire::dispatch::{Hex, Snapshot};
    Snapshot::Prepared {
        marker: Hex::parse(&"c".repeat(32)).unwrap(),
        prepared_sha256: Hex::parse(&"b".repeat(64)).unwrap(),
        source_sha: Hex::parse(&"d".repeat(40)).unwrap(),
        platform: None,
        stage: None,
    }
}

#[test]
fn ordinary_main_selection_has_purpose_absent_native_hash_and_command_only_none() {
    let selected: d::Selection = serde_json::from_str(ORDINARY).unwrap();
    assert!(selected.valid() && selected.retained_fits());
    assert!(selected.legacy().is_none());
    assert_eq!(selected.kind(), wire::Kind::SetupPrepare);
    let i = selected.input().unwrap();
    assert_eq!(serde_json::to_string(&i).unwrap(), ORDINARY);
    assert_eq!(i.hash().unwrap(), p::digest(ORDINARY.as_bytes()));
    assert_eq!(
        wire::Kind::SetupPrepare.consent(),
        "agent-setup-prepare-once-v1"
    );
    assert_ne!(
        wire::Kind::SetupPrepare.consent(),
        wire::Kind::SetupPublish.consent()
    );
    assert!(matches!(
        wire::Kind::SetupPrepare.action(),
        crate::service_protocol::Action::GitHubSetupPrepare
    ));
    assert!(serde_json::from_str::<wire::Selection>(ORDINARY).is_err()); // CLI still takes IDs only
    assert!(i.preflight_command().is_err() && i.release_command().is_err());
    let command = i.counter_command().unwrap();
    assert!(i.matches_counter(&command));
    let p::Command::Prepare(mut args) = command else {
        panic!("not original Prepare")
    };
    assert!(args.purpose.is_none() && args.valid());
    assert_eq!(
        serde_json::to_string(&args).unwrap(),
        r#"{"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":12,"base":"release/setup","purpose":null}"#
    );
    args.purpose = Some(p::counter::Purpose::Counter);
    assert!(!i.matches_counter(&p::Command::Prepare(args)));
    let mut old: Value = serde_json::from_str(ORDINARY).unwrap();
    old["kind"] = json!("counter-prepare");
    old["purpose"] = json!("version-counter");
    let old = serde_json::from_value::<d::Selection>(old)
        .unwrap()
        .input()
        .unwrap();
    assert!(old.valid());
    assert_eq!(
        serde_json::to_string(&old).unwrap(),
        r#"{"kind":"counter-prepare","sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":12,"base":"release/setup","purpose":"version-counter"}"#
    );
    for (key, value) in [
        ("purpose", Value::Null),
        ("purpose", json!("version-counter")),
        ("purpose", json!("setup-pr")),
        ("files", json!([])),
        ("home", json!("inert")),
        ("token", json!("inert")),
        ("url", json!("https://invalid.invalid")),
        ("confirm", json!(true)),
    ] {
        let mut bad: Value = serde_json::from_str(ORDINARY).unwrap();
        bad[key] = value;
        assert!(
            serde_json::from_value::<d::Selection>(bad).is_err(),
            "{key}"
        );
    }
    assert!(serde_json::from_str::<d::Selection>(
        &ORDINARY.replace("\"base\":", "\"base\":\"main\",\"base\":")
    )
    .is_err());
}

#[test]
fn ordinary_selection_keeps_original_scalar_and_real_capacity_bounds() {
    for (key, value) in [
        ("expectedRevision", json!(0)),
        ("expectedRevision", json!(u32::MAX)),
        ("expectedConnectionRevision", json!(0)),
        ("expectedConnectionRevision", json!(u32::MAX)),
        ("base", json!("../main")),
        ("sessionId", json!("bad session")),
    ] {
        let mut bad: Value = serde_json::from_str(ORDINARY).unwrap();
        bad[key] = value;
        assert!(!serde_json::from_value::<d::Selection>(bad).unwrap().valid());
    }
    let mut selected: d::Selection = serde_json::from_str(ORDINARY).unwrap();
    assert_eq!(selected.limit(), 4096);
    assert!(selected.input().unwrap().heap().unwrap() <= d::INPUT_BACKING);
    if let d::Selection::SetupPrepare(v) = &mut selected {
        v.base.reserve_exact(d::INPUT_BACKING + 1);
    }
    assert!(selected.valid()); // content length cannot conceal retained capacity
    assert!(!selected.retained_fits());
    assert_eq!(wire::RAW_LIMIT, 1024);
    assert_eq!(wire::REQUEST_LIMIT, 32);
    assert!(reference().valid() && reference().retained_fits());
    assert!(!wire::Kind::SetupPrepare.mutation());
    assert_eq!(wire::Kind::SetupPrepare.go_effect(), wire::Effect::None);
    for effect in [
        wire::Effect::NotSent,
        wire::Effect::PotentiallyApplied,
        wire::Effect::DraftPrObserved,
        wire::Effect::CounterObserved,
    ] {
        assert!(!effect.valid_for(wire::Kind::SetupPrepare));
    }
}

#[test]
fn ordinary_compact_result_is_read_only_and_hashes_the_full_native_five_file_review() {
    let at = Instant::now();
    let (mut state, _edit, _doc, _root, _control) =
        super::super::super::tests::fixture(p::Kind::Prepare, at);
    let active = state.publication.active.take().unwrap();
    let mut prepared = super::super::super::tests::request(p::Kind::Publish)
        .prepared
        .unwrap();
    let _original = active; // retained unentered Prepare fixture, not a publish ticket
    let p::Review::Setup(full) = &mut prepared else {
        panic!("not ordinary fixture")
    };
    for (i, file) in full.files.iter_mut().enumerate() {
        let maximum = if i == 0 { 65536 } else { 16384 };
        file.before = Some("x".repeat(maximum));
        file.after = "y".repeat(maximum);
    }
    full.files[0].after.replace_range(..10, "é\n\"\\\u{2028}");
    assert!(prepared.valid());
    let encoded = serde_json::to_vec(&prepared).unwrap();
    assert!(encoded.len() > 250_000 && encoded.len() <= p::REVIEW_LIMIT);
    assert_eq!(d::hash(&prepared).unwrap(), p::digest(&encoded));
    state.publication.view.consent = Some(p::ConsentView {
        id: "c".repeat(32),
        expires_at: "2026-10-22T12:00:00Z".into(),
        prepared,
    });
    let snapshot = state.counter_compact(&reference()).unwrap().unwrap();
    assert!(snapshot.valid_for(wire::Kind::SetupPrepare));
    assert!(snapshot.allocated().unwrap() <= wire::dispatch::SNAPSHOT_BACKING);
    let raw = serde_json::to_vec(&snapshot).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(value["preparedSha256"], p::digest(&encoded));
    assert_eq!(value["sourceSha"], "d".repeat(40));
    assert!(value["platform"].is_null() && value["stage"].is_null());
    assert!(raw.len() < wire::RAW_LIMIT && !String::from_utf8(raw).unwrap().contains("files"));
    let wire::Review::SetupPrepare(r) = reference() else {
        unreachable!()
    };
    assert!(state
        .counter_compact(&wire::Review::CounterPrepare(r))
        .is_err());
    assert!(!snapshot.valid_for(wire::Kind::SetupPublish));
    let mut wrong = value;
    wrong["platform"] = json!("android");
    assert!(!serde_json::from_value::<wire::dispatch::Snapshot>(wrong)
        .unwrap()
        .valid_for(wire::Kind::SetupPrepare));
}

#[test]
fn ordinary_prepare_producer_needs_native_caller_and_history_before_a_separate_publish() {
    let at = Instant::now();
    let (mut state, edit, doc, root, control) =
        super::super::super::tests::fixture(p::Kind::Prepare, at);
    let active = state.publication.active.take().unwrap();
    let operation = active.ticket.operation_id().to_owned();
    let prepared = super::super::super::tests::request(p::Kind::Publish)
        .prepared
        .unwrap();
    let (_row_doc, inbox, call, e) = entry(at);
    state.publication.view.available = true;
    state.publication.view.reason = p::Reason::None;
    state.publication.view.consent = Some(p::ConsentView {
        id: active.consent_id.clone(),
        expires_at: "2026-10-22T12:00:00Z".into(),
        prepared: prepared.clone(),
    });
    state.publication.consent = Some(Consent {
        producer: Some(d::Producer::new(&e, &operation)),
        identity: Arc::new(()),
        agent: None,
        id: active.consent_id.clone(),
        prepared,
        counter_proof: None,
        end: at + Duration::from_secs(30),
        session_id: active.session_id,
        project_id: active.project_id,
        generation: active.generation,
        root: active.root,
        stamp: active.stamp, // sole original fixture stamp, never cloned
    });
    let selected = wire::Selection::SetupPublish(wire::PreparedSelection {
        session_id: "github-session-1".into(),
        consent_id: active.consent_id,
        expected_revision: state.publication.view.revision,
    });
    let guard = edit.saved_registration_guard(&doc).unwrap();
    assert!(state
        .publication_agent_review(&selected, 2, &root, &guard, at)
        .is_err());
    e.entering().unwrap();
    e.arm(&operation).unwrap();
    e.go(&operation).unwrap();
    state.counter_agent_return(&e, &operation, p::Reason::None, p::Effect::None);
    assert!(state
        .publication_agent_review(&selected, 2, &root, &guard, at)
        .is_err());
    call.returned(Ok(()));
    assert!(state
        .publication_agent_review(&selected, 2, &root, &guard, at)
        .is_err());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let publish = state
        .publication_agent_review(&selected, 2, &root, &guard, at)
        .unwrap();
    assert_eq!(publish.data.kind(), wire::Kind::SetupPublish);
    assert!(e.scope().current(false).is_err()); // producer is not the retired consumer
    assert!(state.publication_agent_allow(&publish, e.scope()).is_err()); // no upgrade of Prepare grant
    let mut other = root.clone();
    other.path.push("other");
    assert!(state
        .publication_agent_review(&selected, 2, &other, &guard, at)
        .is_err());
    assert!(state
        .publication_agent_review(&selected, 3, &root, &guard, at)
        .is_err());
    assert!(state
        .publication_agent_review(&selected, 2, &root, &guard, publish.end)
        .is_err());
    let fresh = request::NativeScope::new(
        id(1),
        "project-1".into(),
        "/never-opened-publish".into(),
        1,
        2,
        3,
        publish.data.clone(),
        publish.identity.clone(),
        publish.end,
        Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                at + Duration::from_secs(80),
            ),
        ),
        Arc::downgrade(&doc),
        tokio::sync::watch::channel(1).0,
    );
    state.publication_agent_allow(&publish, &fresh).unwrap();
    inbox.revoke(wire::Reason::PermissionRevoked, at).unwrap();
    state.counter_agent_revoke(e.scope());
    assert!(state
        .publication
        .consent
        .as_ref()
        .unwrap()
        .agent
        .as_ref()
        .unwrap()
        .upgrade()
        .is_some_and(|s| Arc::ptr_eq(&s, &fresh)));
    assert!(e.positively_returned(&operation)); // old completed cancellation cannot erase successor
    assert!(control.retained()); // no native ticket completion has been fabricated by this fixture
}

#[test]
fn lost_prepare_native_caller_or_history_never_becomes_a_ready_producer() {
    for fault in 0..4 {
        let at = Instant::now();
        let (_doc, inbox, call, e) = entry(at);
        let operation = "github-publication-1";
        let producer = d::Producer::new(&e, operation);
        e.entering().unwrap();
        e.arm(operation).unwrap();
        e.go(operation).unwrap();
        if fault == 0 {
            e.unknown(wire::Reason::CleanupUnknown);
        }
        if fault == 3 {
            e.scope().revoke(wire::Reason::PermissionRevoked, at);
        }
        e.dispatch_returned(
            operation,
            wire::Reason::None,
            wire::Effect::None,
            Some(compact()),
        );
        if fault == 1 {
            drop(call);
        } else {
            call.returned(Ok(()));
        }
        if let Some(history) = e.claim_history().unwrap() {
            if fault == 2 {
                assert!(history.returned(Err(Error::StateUnknown)).is_err());
            } else {
                history.returned(Ok(())).unwrap();
            }
        }
        assert!(!producer.positive(), "fault={fault}");
        assert!(!e.positively_returned("github-publication-2"));
        assert!(inbox
            .submit(wire::Submit {
                origin: e.origin().clone(),
                grant_id: id(3)
            })
            .is_err());
        // No returned compact DATA or late success clears an absorbing Unknown.
        if fault < 3 {
            e.dispatch_returned(
                operation,
                wire::Reason::None,
                wire::Effect::None,
                Some(compact()),
            );
            assert!(!producer.positive());
        }
    }
}
