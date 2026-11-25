//! Closed DATA tables only. No grant, native owner, provider or filesystem.
use super::super as p;
use super::*;
use serde_json::{json, Value};

pub(crate) const CANDIDATE: &str = "12345678-1234-4234-8234-123456789abc";
const STAGE: &str = "22345678-1234-4234-8234-123456789abc";
const PREDECESSOR: &str = "32345678-1234-4234-8234-123456789abc";
pub(crate) fn cases() -> Vec<(Kind, Platform, Mode)> {
    let mut out = Vec::new();
    for platform in [Platform::Android, Platform::Ios] {
        for mode in [
            Mode::CandidateUpload,
            Mode::ExternalTesting,
            Mode::ProductionSubmit,
        ] {
            out.push((Kind::Execute, platform, mode));
        }
        out.push((Kind::Reconcile, platform, Mode::CurrentInternal));
    }
    out.push((Kind::Reconcile, Platform::Android, Mode::RecoverySettlement));
    out.push((Kind::Reconcile, Platform::Ios, Mode::ExternalReadiness));
    out
}
pub(crate) fn review(kind: Kind, platform: Platform, mode: Mode) -> p::Review {
    let staged = matches!(
        mode,
        Mode::ExternalTesting | Mode::ProductionSubmit | Mode::ExternalReadiness
    );
    p::Review {
        kind,
        platform,
        operation_id: crate::service_protocol::Id::parse(&"a".repeat(32)).unwrap(),
        owner_generation: crate::service_protocol::Id::parse(&"b".repeat(32)).unwrap(),
        status_revision: 3,
        saved_config: p::Content {
            bytes: 100,
            sha256: "c".repeat(64),
        },
        saved_version: p::Version {
            bytes: 40,
            sha256: "d".repeat(64),
            name: "1.2.3".into(),
            build: 42,
        },
        candidate: Some(Candidate {
            operation_id: CANDIDATE.into(),
            sha256: "e".repeat(64),
        }),
        release: Some(Review {
            mode,
            intent_sha256: "f".repeat(64),
            stage_operation_id: staged.then(|| STAGE.into()),
            basis: staged.then(|| Basis {
                operation_id: match mode {
                    Mode::ExternalTesting => CANDIDATE,
                    Mode::ExternalReadiness => STAGE,
                    _ => PREDECESSOR,
                }
                .into(),
                receipt_sha256: "1".repeat(64),
            }),
        }),
    }
}
pub(crate) fn report(r: &p::Review) -> p::Report {
    let d = r.release.as_ref().unwrap();
    let c = r.candidate.as_ref().unwrap();
    let value = Receipt {
        mode: d.mode,
        head_sequence: *d.mode.heads().start(),
        operation_id: d
            .stage_operation_id
            .as_ref()
            .unwrap_or(&c.operation_id)
            .clone(),
        candidate_operation_id: c.operation_id.clone(),
        candidate_sha256: c.sha256.clone(),
        intent_sha256: d.intent_sha256.clone(),
        receipt_sha256: "2".repeat(64),
        basis: d.basis.clone(),
        target: d.mode.target(r.platform),
        result: match d.mode {
            Mode::CurrentInternal | Mode::RecoverySettlement => ResultKind::Reconciled,
            Mode::ExternalReadiness => ResultKind::Ready,
            _ => ResultKind::Accepted,
        },
        state: match d.mode {
            Mode::ExternalTesting | Mode::ExternalReadiness => Some(StoreState::AvailableToTesters),
            Mode::ProductionSubmit if r.platform == Platform::Android => Some(StoreState::Draft),
            Mode::ProductionSubmit => Some(StoreState::PendingDeveloperRelease),
            _ => None,
        },
        limitations: d.mode.limitations(),
    };
    if r.kind == Kind::Execute {
        p::Report::Execute { release: value }
    } else {
        p::Report::Reconcile { release: value }
    }
}

#[test]
fn store_release_exact_ten_pairs_have_distinct_non_upgrading_consent() {
    let rows = cases();
    assert_eq!(rows.len(), 10);
    let mut consents = std::collections::BTreeSet::new();
    for (kind, platform, mode) in &rows {
        let r = review(*kind, *platform, *mode);
        assert!(r.valid());
        let consent = r.consent().unwrap();
        assert!(consents.insert(consent));
        assert!(consent.ends_with("-once-v1"));
        assert!(![
            "agent-android-store-access-once-v1",
            "agent-ios-store-candidate-prepare-once-v1",
            "release"
        ]
        .contains(&consent));
        assert_eq!(serde_json::from_value::<p::Review>(json!(r)).unwrap(), r);
    }
    for kind in [
        Kind::AccessCheck,
        Kind::CandidatePrepare,
        Kind::Execute,
        Kind::Reconcile,
    ] {
        for platform in [Platform::Android, Platform::Ios] {
            for mode in [
                Mode::CandidateUpload,
                Mode::ExternalTesting,
                Mode::ProductionSubmit,
                Mode::CurrentInternal,
                Mode::RecoverySettlement,
                Mode::ExternalReadiness,
            ] {
                assert_eq!(
                    mode.consent(kind, platform).is_some(),
                    rows.contains(&(kind, platform, mode))
                );
                assert_eq!(
                    review(kind, platform, mode).valid(),
                    rows.contains(&(kind, platform, mode))
                );
            }
        }
    }
}

#[test]
fn store_release_old_eight_fields_stay_exact_without_nullable_upgrade() {
    let mut r = review(Kind::Execute, Platform::Android, Mode::CandidateUpload);
    r.release = None;
    for kind in [Kind::AccessCheck, Kind::CandidatePrepare] {
        r.kind = kind;
        r.candidate = (kind == Kind::CandidatePrepare).then(|| Candidate {
            operation_id: CANDIDATE.into(),
            sha256: "e".repeat(64),
        });
        let v = json!(r);
        assert_eq!(v.as_object().unwrap().len(), 8);
        assert!(v.get("release").is_none());
        assert_eq!(serde_json::from_value::<p::Review>(v.clone()).unwrap(), r);
        let mut extra = v;
        extra["release"] = Value::Null;
        assert!(serde_json::from_value::<p::Review>(extra).is_err());
        assert!(r.consent().unwrap().contains(if kind == Kind::AccessCheck {
            "access"
        } else {
            "candidate-prepare"
        }));
    }
    for value in [Value::Null, json!({})] {
        let mut v = json!(review(
            Kind::Execute,
            Platform::Android,
            Mode::CandidateUpload
        ));
        v["release"] = value;
        assert!(serde_json::from_value::<p::Review>(v).is_err());
    }
}

#[test]
fn store_release_review_requires_exact_candidate_intent_and_lineage() {
    for (kind, platform, mode) in cases() {
        let r = review(kind, platform, mode);
        for field in ["mode", "intentSha256", "stageOperationId", "basis"] {
            let mut v = json!(r);
            v["release"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<p::Review>(v).is_err());
        }
        for (field, value) in [
            ("intentSha256", json!("A".repeat(64))),
            ("credential", json!("private")),
            ("stageOperationId", json!(CANDIDATE)),
        ] {
            let mut v = json!(r);
            v["release"][field] = value;
            assert!(serde_json::from_value::<p::Review>(v).is_err());
        }
        let mut v = json!(r);
        v["candidate"] = Value::Null;
        assert!(serde_json::from_value::<p::Review>(v).is_err());
        let mut v = json!(r);
        v["release"]["basis"] = json!({"operationId":"42345678-1234-4234-8234-123456789abc","receiptSha256":"1".repeat(64)});
        if mode == Mode::ProductionSubmit {
            assert!(serde_json::from_value::<p::Review>(v).is_ok());
        } else {
            assert!(serde_json::from_value::<p::Review>(v).is_err());
        }
    }
}

#[test]
fn store_release_receipts_preserve_mode_state_and_non_finality_limitations() {
    for (kind, platform, mode) in cases() {
        let r = review(kind, platform, mode);
        let good = report(&r);
        assert!(good.valid_for(&r));
        let raw = json!(good);
        assert_eq!(raw.as_object().unwrap().len(), 2);
        let receipt = &raw["release"];
        assert_eq!(receipt["target"], json!(mode.target(platform)));
        assert_eq!(receipt["limitations"], json!(mode.limitations()));
        for (field, value) in [
            ("candidateSha256", json!("3".repeat(64))),
            ("intentSha256", json!("3".repeat(64))),
            ("operationId", json!(PREDECESSOR)),
            ("headSequence", json!(0)),
            ("headSequence", json!(514)),
            ("limitations", json!([])),
            ("state", json!("released")),
            ("target", json!("public")),
            ("retryAllowed", json!(true)),
        ] {
            let mut v = raw.clone();
            v["release"][field] = value;
            assert!(!serde_json::from_value::<p::Report>(v).is_ok_and(|p| p.valid_for(&r)));
        }
        for (other_kind, other_platform, other_mode) in cases() {
            if (kind, platform, mode) != (other_kind, other_platform, other_mode) {
                let other = review(other_kind, other_platform, other_mode);
                assert!(!good.valid_for(&other));
            }
        }
    }
}

#[test]
fn store_release_ios_review_states_never_become_tester_or_public_readiness() {
    for mode in [Mode::ExternalTesting, Mode::ProductionSubmit] {
        let r = review(Kind::Execute, Platform::Ios, mode);
        for state in ["submitted-for-review", "in-review", "approved"] {
            let mut v = json!(report(&r));
            v["release"]["state"] = json!(state);
            assert!(serde_json::from_value::<p::Report>(v.clone())
                .unwrap()
                .valid_for(&r));
            assert_eq!(v["release"]["result"], "accepted");
            v["release"]["result"] = json!("ready");
            assert!(!serde_json::from_value::<p::Report>(v)
                .unwrap()
                .valid_for(&r));
        }
    }
    let r = review(Kind::Execute, Platform::Android, Mode::ExternalTesting);
    assert_eq!(
        json!(report(&r))["release"]["target"],
        "configured-play-external"
    );
}

#[test]
fn store_release_worst_valid_metadata_fits_unchanged_retained_copy_quotes() {
    for (kind, platform, mode) in cases() {
        let mut r = review(kind, platform, mode);
        r.status_revision = u32::MAX - 1;
        r.saved_config.bytes = 524288;
        r.saved_version.bytes = 65536;
        r.saved_version.name = "v".repeat(64);
        r.saved_version.build = 2_100_000_000;
        assert!(r.valid());
        let review_bytes = serde_json::to_vec(&r).unwrap();
        assert!(review_bytes.len() <= 2048);
        let result_bytes = serde_json::to_vec(&report(&r)).unwrap();
        assert!(result_bytes.len() <= 2048);
        // Charge fixed struct/string/vector backing conservatively as well as
        // retained content. Full native Context/material is charged elsewhere.
        let copies = std::mem::size_of::<p::Review>()
            + review_bytes.len() * 2
            + std::mem::size_of::<p::Report>()
            + result_bytes.len() * 2
            + 1024;
        assert!(copies <= 8192, "bounded small review+result copy: {copies}");
        assert_eq!(p::DOCUMENT_BACKING, 2 * 1024 * 1024);
    }
}
