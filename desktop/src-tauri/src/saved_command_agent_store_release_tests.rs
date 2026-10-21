//! Original wire decoders/Saved guards, with inert DATA and unentered owners.
//! A decoded fixture is never claimed as native retirement or provider proof.
use super::*;
use p::release::{tests as data, Mode};
use serde_json::{json, Value};
const AUTH: &str = "23456789-1234-4234-8234-123456789abc";

fn raw(mode: Mode, ios: bool) -> (Context, Value) {
    if matches!(mode, Mode::ExternalTesting | Mode::ProductionSubmit) {
        let production = mode == Mode::ProductionSubmit;
        let c = execute_wire::prepare(&execute_wire::tests::stage_input(ios, production))
            .unwrap()
            .context();
        let mut v = execute_wire::tests::stage_complete(ios, production);
        if !ios && !production {
            v["result"]["executionReceipt"]["destination"]["channel"] = json!("qa-beta");
        }
        return (Context::LocalStoreExecute(c), v);
    }
    if mode == Mode::ExternalReadiness {
        return (
            Context::LocalStoreReconcile(reconcile_wire::tests::readiness_context()),
            reconcile_wire::tests::readiness_terminal(12),
        );
    }
    let mut v = reconcile_wire::tests::terminal();
    let mut input = reconcile_wire::tests::input();
    if ios {
        input["platform"] = json!("ios");
        input["confirmation"] = json!("candidate:ios:1.2.3:42");
    }
    let c = if mode == Mode::CandidateUpload {
        let mut input = execute_wire::tests::input();
        if ios {
            input["platform"] = json!("ios");
            input["confirmation"] = json!("candidate:ios:1.2.3:42");
            input.as_object_mut().unwrap().remove("toolchainSelection");
        }
        let c = execute_wire::prepare(&input).unwrap().context();
        v["context"] = json!(c);
        let mut r = v["result"]["reconciliationReceipt"].take();
        for key in ["observation", "priorExecutionFinality"] {
            r.as_object_mut().unwrap().remove(key);
        }
        r["result"] = json!("accepted");
        r["limitations"] = json!([
            "internal-testing-only",
            "not-public-release",
            "prior-prepare-finality-not-established",
            "saved-inputs-not-atomic"
        ]);
        v["result"] = json!({"schemaVersion":1,"scope":if ios {"local-ios-store-execute"} else {"local-android-store-execute"},"headSequence":7,"executionReceipt":r});
        v["lifetime"]["commands"] = json!(if ios { 16 } else { 14 });
        Context::LocalStoreExecute(c)
    } else {
        if mode == Mode::RecoverySettlement {
            input["settlement"] = json!("record-current-target");
        }
        let c = reconcile_wire::prepare(&input).unwrap().context();
        v["context"] = json!(c);
        v["lifetime"]["commands"] = json!(if ios { 15 } else { 14 });
        v["result"]["scope"] = json!(if mode == Mode::RecoverySettlement {
            "local-android-recovery-settlement"
        } else if ios {
            "local-ios-store-reconcile"
        } else {
            "local-android-store-reconcile"
        });
        v["result"]["headSequence"] = json!(if mode == Mode::RecoverySettlement {
            7
        } else {
            6
        });
        Context::LocalStoreReconcile(c)
    };
    if ios {
        let key = if mode == Mode::CandidateUpload {
            "executionReceipt"
        } else {
            "reconciliationReceipt"
        };
        let r = v["result"][key].as_object_mut().unwrap();
        r.remove("applicationId");
        r.insert("bundleId".into(), json!("dev.example.ios-app"));
        r.insert("appStoreAppId".into(), json!("0012345"));
        r.insert(
            "destination".into(),
            json!({"channel":"testflight-internal"}),
        );
        if mode != Mode::CandidateUpload {
            r.insert("observation".into(), json!("current-internal-build-only"));
        }
    }
    (c, v)
}
fn frame(protocol: &str, seq: u32, kind: &str, payload: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"protocol":protocol,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),"sequence":seq,"kind":kind,"payload":payload})).unwrap();
    bytes.push(b'\n');
    bytes
}
fn decoded(c: &Context, v: &Value) -> Terminal {
    let head = v["result"]["headSequence"].as_u64().unwrap() as u32;
    match c {
        Context::LocalStoreExecute(c) => {
            let mut d = execute_wire::Decoder::new(AUTH).unwrap();
            for (seq, kind, body) in [
                (0, "accepted", json!({"schemaVersion":1,"context":c})),
                (1, "lease-ready", json!({})),
                (
                    2,
                    "history-head",
                    json!({"sequence":head-2,"sha256":"a".repeat(64)}),
                ),
                (
                    3,
                    "execute-pending",
                    json!({"sequence":head-1,"sha256":"b".repeat(64)}),
                ),
                (
                    4,
                    "execute-settled",
                    json!({"head":{"sequence":head,"sha256":"c".repeat(64)},"phase":"settled-success"}),
                ),
            ] {
                d.decode(
                    &frame(execute_wire::PROTOCOL, seq, kind, body),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    c,
                    &"c".repeat(32),
                    &"d".repeat(64),
                )
                .unwrap();
            }
            let out = d
                .decode(
                    &frame(execute_wire::PROTOCOL, 5, "terminal", v.clone()),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    c,
                    &"c".repeat(32),
                    &"d".repeat(64),
                )
                .unwrap();
            assert!(d.finish());
            if let execute_wire::Frame::Terminal(t) = out {
                Terminal::LocalStoreExecute(t)
            } else {
                panic!("terminal required")
            }
        }
        Context::LocalStoreReconcile(c) => {
            let mut d = reconcile_wire::Decoder::new(AUTH).unwrap();
            for (seq, kind, body) in [
                (0, "accepted", json!({"schemaVersion":1,"context":c})),
                (1, "lease-ready", json!({})),
                (
                    2,
                    "history-head",
                    json!({"sequence":head-u32::from(c.checkpointing()),"sha256":"a".repeat(64)}),
                ),
            ] {
                d.decode(
                    &frame(reconcile_wire::PROTOCOL, seq, kind, body),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    c,
                    &"c".repeat(32),
                    &"d".repeat(64),
                )
                .unwrap();
            }
            if c.checkpointing() {
                let (event, phase) = if c.refreshing() {
                    ("external-ready", "external-ready")
                } else {
                    ("recovery-settled", "target-reconciled")
                };
                d.decode(
                    &frame(
                        reconcile_wire::PROTOCOL,
                        3,
                        event,
                        json!({"head":{"sequence":head,"sha256":"b".repeat(64)},"phase":phase}),
                    ),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    c,
                    &"c".repeat(32),
                    &"d".repeat(64),
                )
                .unwrap();
            }
            let out = d
                .decode(
                    &frame(
                        reconcile_wire::PROTOCOL,
                        if c.checkpointing() { 4 } else { 3 },
                        "terminal",
                        v.clone(),
                    ),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    c,
                    &"c".repeat(32),
                    &"d".repeat(64),
                )
                .unwrap();
            assert!(d.finish());
            if let reconcile_wire::Frame::Terminal(t) = out {
                Terminal::LocalStoreReconcile(t)
            } else {
                panic!("terminal required")
            }
        }
        _ => panic!("closed release context"),
    }
}

#[test]
fn store_release_saved_reviews_bind_all_actual_native_modes_and_private_contexts() {
    for (kind, platform, mode) in data::cases() {
        let (c, _) = raw(mode, platform == p::Platform::Ios);
        assert!(witness(&c).is_some());
        let r = review(&c, id('a').as_str(), id('b').as_str(), 3).unwrap();
        assert_eq!(r.kind, kind);
        assert_eq!(r.platform, platform);
        assert_eq!(r.release.as_ref().unwrap().mode, mode);
        assert_eq!(r.consent(), mode.consent(kind, platform));
        let text = serde_json::to_string(&r).unwrap();
        for key in [
            "recordId",
            "supplementalAssignments",
            "toolchainSelection",
            "source",
            "authorizationId",
        ] {
            assert!(!text.contains(key));
        }
    }
    let later = prepare_wire::prepare(&prepare_wire::tests::stage_input(false, false))
        .unwrap()
        .context();
    assert!(witness(&Context::LocalStorePrepare(later)).is_none());
}

#[test]
fn store_release_native_consent_is_distinct_from_every_agent_token() {
    for (kind, platform, mode) in data::cases() {
        let (c, _) = raw(mode, platform == p::Platform::Ios);
        let r = review(&c, id('a').as_str(), id('b').as_str(), 3).unwrap();
        let value = |consent| json!({"operationId":id('a'),"ownerGeneration":id('b'),"consentVersion":consent});
        match &c {
            Context::LocalStoreExecute(c) => {
                assert!(execute_wire::start(&value(c.consent()))
                    .unwrap()
                    .matches_context(c));
                for consent in [
                    r.consent().unwrap(),
                    "agent-android-store-access-once-v1",
                    "local-android-store-prepare-v1",
                    "release",
                ] {
                    assert!(execute_wire::start(&value(consent)).is_err());
                }
            }
            Context::LocalStoreReconcile(c) => {
                assert!(reconcile_wire::start(&value(c.consent())).is_ok());
                for consent in [
                    r.consent().unwrap(),
                    "agent-android-store-access-once-v1",
                    "local-android-store-execute-v1",
                    "release",
                ] {
                    assert!(reconcile_wire::start(&value(consent)).is_err());
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(r.kind, kind);
    }
}

#[test]
fn store_release_validated_native_results_redact_private_receipt_and_preserve_real_mode() {
    for (kind, platform, mode) in data::cases() {
        let (c, raw) = raw(mode, platform == p::Platform::Ios);
        let t = decoded(&c, &raw);
        let r = review(&c, id('a').as_str(), id('b').as_str(), 3).unwrap();
        let result = report(&t, &r).unwrap();
        assert!(result.valid_for(&r));
        let bytes = serde_json::to_vec(&result).unwrap();
        assert!(bytes.len() < 2048);
        let text = String::from_utf8(bytes).unwrap();
        for key in [
            "authorizationId",
            "sourceCommit",
            "sourceTree",
            "appStoreAppId",
            "applicationId",
            "bundleId",
            "destination",
            "observedAt",
            "supplementalAssignments",
        ] {
            assert!(!text.contains(key));
        }
        if platform == p::Platform::Android && mode == Mode::ExternalTesting {
            assert_eq!(
                raw["result"]["executionReceipt"]["destination"]["channel"],
                "qa-beta"
            );
            assert_eq!(
                json!(result)["release"]["target"],
                "configured-play-external"
            );
            assert!(!text.contains("qa-beta")); // Exact track stays with native review, not a coerced target.
        }
        let mut wrong = r.clone();
        wrong.release.as_mut().unwrap().intent_sha256 = "9".repeat(64);
        assert!(report(&t, &wrong).is_err());
        assert_eq!(r.kind, kind);
    }
}

#[test]
fn store_release_decoded_terminal_is_not_positive_native_retirement() {
    for mode in [
        Mode::CandidateUpload,
        Mode::RecoverySettlement,
        Mode::ExternalReadiness,
    ] {
        let (c, raw) = raw(mode, mode == Mode::ExternalReadiness);
        let t = decoded(&c, &raw);
        let r = review(&c, id('a').as_str(), id('b').as_str(), 3).unwrap();
        let mut value = projected(c);
        value.phase = Phase::Terminal;
        value.intent_usable = false;
        value.outcome = Some(Outcome::Complete);
        value.result = Some(t);
        let control = requests::Control::new();
        let pending = projection(&value, 4, false, &r, &control).unwrap();
        assert!(!pending.retired);
        assert!(pending.result.is_none());
        assert!(pending.outcome.is_none());
        assert!(projection(&value, 4, true, &r, &control)
            .unwrap()
            .result
            .is_some());
        value.phase = Phase::Unknown;
        assert!(projection(&value, 5, true, &r, &control).is_err());
    }
}

#[test]
fn store_release_old_link_or_missing_execute_budget_refuses_before_take() {
    for domain in [
        SavedCommandDomain::LocalStoreExecute,
        SavedCommandDomain::LocalStoreReconcile,
    ] {
        let (_old, mut prepared, link, inbox, _doc) = binding();
        let entry = inbox.entries().unwrap().remove(0);
        link.attach(&entry).unwrap();
        prepared.projection.context = raw(
            if domain == SavedCommandDomain::LocalStoreExecute {
                Mode::CandidateUpload
            } else {
                Mode::CurrentInternal
            },
            false,
        )
        .0;
        assert!(!start_matches(&prepared, Some(&entry)));
        assert!(!start_matches(&prepared, None));
        let owner =
            SavedCommandOwner::new(RuntimeConfig::packaged("/inert/unopened".into()), domain);
        owner.inner.lock().prepared = Some(prepared);
        assert!(owner
            .start_bound_requests_store(
                Start {
                    operation_id: id('a').as_str().into(),
                    owner_generation: id('b').as_str().into()
                },
                entry.submitted_at(),
                Some((1, root())),
                Availability::from_store(store_wire::Availability::Available),
                None,
                None,
                None,
                None,
                None,
                Some(&entry)
            )
            .is_err());
        assert!(owner.inner.lock().prepared.is_some());
        assert!(!link.consumed.load(Ordering::Acquire));
        // Original no-material review cannot mint new approval, either.
        assert!(owner
            .store_approval(
                if domain == SavedCommandDomain::LocalStoreExecute {
                    p::Kind::Execute
                } else {
                    p::Kind::Reconcile
                },
                &id('a'),
                &id('b'),
                0
            )
            .is_err());
        owner.inner.lock().prepared.take();
    }
}
