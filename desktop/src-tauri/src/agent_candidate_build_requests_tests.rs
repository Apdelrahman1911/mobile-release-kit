//! Pure existing Inbox/Entry/READ control transitions and public DATA bounds.
//! No material, native task, journal ACK or build qualification is manufactured.
use super::*;
use crate::{agent_candidate_build as candidate, service_version_reserve_requests::ReadPermission};
const OPERATION: &str = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa";
fn scope(f: &Fixture, family: Family, read: Arc<ReadPermission>) -> Arc<NativeScope> {
    let mut scope = f.scope(family);
    let s = Arc::get_mut(&mut scope).unwrap();
    s.read = Some(read);
    match &mut s.review {
        Review::Android(r) => {
            r.mode = android::Mode::SavedAndroidCandidateInputs;
            r.upload_certificate_sha256 = Some("d".repeat(64));
            r.signing = Some(android::signed::Selection {
                mode: android::signed::SigningMode::LocalUploadKey,
                assignments: vec![android::signed::Assignment {
                    kind: android::signed::Kind::AndroidKeystore,
                    record_id: id(8),
                    record_revision: 1,
                    context_revision: 1,
                }],
            });
        }
        Review::Ios(r) => {
            r.mode = ios::Mode::SavedIosCandidateInputs;
            r.signing = Some(ios::signed::Review {
                team_id: "ABCDE12345".into(),
                distribution_certificate_sha256: "d".repeat(64),
                firebase: false,
                project_read_token: false,
            });
        }
        _ => panic!("candidate saved-build fixture only"),
    }
    scope
}
fn bind(f: &Fixture, s: &Arc<NativeScope>) -> (Prepare, Arc<NativeLink>, Claim) {
    let family = s.review.family();
    f.inbox.allow(s.clone()).unwrap();
    let p = f.request(3);
    f.inbox.prepare(family, p.clone(), &f.point).unwrap();
    let claim = f.inbox.claim(family).unwrap().unwrap();
    let link = claim
        .entry()
        .bind(
            family,
            Id::parse(OPERATION).unwrap(),
            id(5),
            1,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
    (p, link, claim)
}
fn start(p: &Prepare) -> Start {
    Start {
        origin: p.query(),
        operation_id: Id::parse(OPERATION).unwrap(),
        owner_generation: id(5),
    }
}
fn summary() -> candidate::Candidate {
    candidate::Candidate {
        operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        head_sequence: 3,
        candidate_sha256: "c".repeat(64),
        source_commit: "a".repeat(40),
        source_tree: "b".repeat(40),
        primary_bytes: 1024,
        primary_sha256: "f".repeat(64),
    }
}
fn completed(link: &NativeLink) -> Operation {
    let mut op = link
        .entry()
        .latest
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .as_ref()
        .clone();
    match &mut op {
        Operation::Android(o) => {
            use android::FindingStatus::*;
            o.status_revision = 2;
            o.state = OperationState::Succeeded;
            o.settlement = Settlement::Settled;
            o.outcome = Some(android::Outcome::Complete);
            o.stage = Some(android::Stage::DisposingWork);
            o.disposition = Some(android::Disposition {
                work: android::WorkDisposition::Removed,
                artifacts: android::ArtifactDisposition::RetainedLocalResult,
            });
            o.result = Some(android::Report {
                scope: android::Scope::LocalAndroidCandidateInputs,
                used_config: link
                    .entry()
                    .scope()
                    .review
                    .android()
                    .unwrap()
                    .saved_config
                    .clone(),
                used_version: link
                    .entry()
                    .scope()
                    .review
                    .android()
                    .unwrap()
                    .saved_version
                    .clone(),
                findings: vec![
                    android::Finding {
                        ordinal: 0,
                        check: android::Check::Signature,
                        status: Pass,
                    },
                    android::Finding {
                        ordinal: 1,
                        check: android::Check::Signer,
                        status: Pass,
                    },
                ],
                summary: android::Summary {
                    total: 2,
                    shown: 2,
                    omitted: 0,
                    counts: [
                        Pass,
                        Fail,
                        Missing,
                        Blocked,
                        Invalid,
                        Skip,
                        Manual,
                        Configured,
                        NotApplicable,
                    ]
                    .into_iter()
                    .map(|s| (s, if s == Pass { 2 } else { 0 }))
                    .collect(),
                },
                artifact: android::Artifact {
                    size: 1024,
                    sha256: "f".repeat(64),
                },
                signing: Some(android::signed::Report {
                    mode: android::signed::SigningMode::LocalUploadKey,
                    upload_certificate_sha256: "d".repeat(64),
                    signature: android::signed::Signature::Passed,
                    signer: android::signed::Signer::MatchesSavedUploadCertificate,
                }),
                candidate: Some(summary()),
            });
        }
        Operation::Ios(o) => {
            o.status_revision = 2;
            o.state = OperationState::Succeeded;
            o.settlement = Settlement::Settled;
            o.outcome = Some(ios::Outcome::Complete);
            o.stage = Some(ios::Stage::DisposingWork);
            o.disposition = Some(ios::Disposition {
                snapshot: ios::SnapshotDisposition::Removed,
                work: ios::WorkDisposition::Removed,
                output: ios::OutputDisposition::RetainedLocalResult,
            });
            o.result = Some(ios::Report {
                scope: ios::Scope::LocalIosCandidateInputs,
                used_config: link
                    .entry()
                    .scope()
                    .review
                    .ios()
                    .unwrap()
                    .saved_config
                    .clone(),
                used_version: link
                    .entry()
                    .scope()
                    .review
                    .ios()
                    .unwrap()
                    .saved_version
                    .clone(),
                entries: 1,
                bytes: 1024,
                export: Some(ios::signed::Export {
                    ipa_bytes: 1024,
                    pairing: ios::signed::Pairing {
                        native_paths: 1,
                        native_identities: 1,
                        present_symbol_slices: 0,
                    },
                }),
                candidate: Some(summary()),
            });
        }
        _ => panic!("candidate saved-build fixture only"),
    }
    assert!(op.valid_for(&link.entry().scope().review));
    op
}
#[test]
fn candidate_prepare_and_terminal_require_original_callers_and_history_without_new_start_permission(
) {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new();
        let s = scope(
            &f,
            family,
            Arc::new(ReadPermission::new(
                Instant::now() + Duration::from_secs(60),
            )),
        );
        let (p, link, preparing) = bind(&f, &s);
        assert!(link.entry().claim_history().unwrap().is_none());
        assert!(f.inbox.start(family, &start(&p)).is_err());
        preparing.returned(true);
        assert!(f.inbox.start(family, &start(&p)).is_err());
        acknowledge(&link);
        f.inbox.start(family, &start(&p)).unwrap();
        let caller = f.inbox.claim(family).unwrap().unwrap();
        link.consume_start(family).unwrap();
        link.publish(completed(&link)).unwrap();
        assert!(link.entry().claim_history().unwrap().is_none());
        assert!(f.inbox.allow(s.clone()).is_err());
        caller.returned(true);
        let (_, data) = link.entry().claim_history().unwrap().unwrap();
        assert!(f.inbox.allow(s.clone()).is_err());
        link.entry()
            .history_returned(data.status_revision(), Ok(()))
            .unwrap();
        assert_eq!(
            link.entry()
                .status()
                .unwrap()
                .operation
                .unwrap()
                .settlement(),
            Settlement::Settled
        );
        assert_eq!(
            f.inbox.start(family, &start(&p)).unwrap().start_state,
            StartState::Consumed
        );
        assert!(f.inbox.claim(family).unwrap().is_none());
    }
}
#[test]
fn candidate_original_read_and_lost_caller_remain_absorbing_after_start() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new();
        let now = Instant::now();
        let read = Arc::new(ReadPermission::new(now + Duration::from_secs(60)));
        let s = scope(&f, family, read.clone());
        assert!(s.valid() && s.matches_read(&read));
        assert!(!s.matches_read(&Arc::new(ReadPermission::new(read.end()))));
        let mut missing = scope(&f, family, read.clone());
        Arc::get_mut(&mut missing).unwrap().read = None;
        assert!(!missing.valid());
        let (p, link, preparing) = bind(&f, &s);
        preparing.returned(true);
        acknowledge(&link);
        f.inbox.start(family, &start(&p)).unwrap();
        let caller = f.inbox.claim(family).unwrap().unwrap();
        link.consume_start(family).unwrap();
        assert_eq!(link.entry().read_end(), Some(read.end()));
        assert_eq!(link.entry().control_poll(), Some(Duration::from_millis(5)));
        link.entry().cancel();
        read.revoke(now);
        assert_eq!(link.entry().stop_at(Instant::now()), Some(now));
        drop(caller);
        link.publish(completed(&link)).unwrap();
        let status = link.entry().status().unwrap();
        assert_eq!(status.request_state, RequestState::AdmissionUnknown);
        assert!(status.operation.is_none() && !status.history_available);
        assert!(link.entry().claim_history().unwrap().is_none());
        assert!(f
            .inbox
            .allow(scope(&f, family, Arc::new(ReadPermission::new(read.end()))))
            .is_err());
    }
}
#[test]
fn candidate_public_report_correlations_and_capacity_use_the_existing_typed_quote() {
    assert!(
        ROW_CEILING <= ROW_BACKING
            && PUBLIC_HEAP_CEILING <= STATUS_HEAP_BYTES
            && ANCILLARY_CEILING <= ANCILLARY_BACKING
    );
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new();
        let s = scope(
            &f,
            family,
            Arc::new(ReadPermission::new(
                Instant::now() + Duration::from_secs(60),
            )),
        );
        let (_, link, preparing) = bind(&f, &s);
        preparing.returned(true);
        let value = completed(&link);
        let heap = value.heap_bytes().unwrap();
        let compact = value.clone().compact().unwrap();
        assert!(compact.heap_bytes().unwrap() <= heap);
        assert!(
            compact.heap_bytes().unwrap() + REVIEW_HEAP_CEILING + 3 * ID_HEAP_BYTES
                <= STATUS_HEAP_BYTES
        );
        let mut no_candidate = value.clone();
        match &mut no_candidate {
            Operation::Android(o) => o.result.as_mut().unwrap().candidate = None,
            Operation::Ios(o) => o.result.as_mut().unwrap().candidate = None,
            _ => unreachable!(),
        }
        assert!(!no_candidate.valid_for(&s.review));
        assert_eq!(
            value.heap_bytes().unwrap() - no_candidate.heap_bytes().unwrap(),
            candidate::HEAP_BYTES
        );
        let mut wrong = value.clone();
        match &mut wrong {
            Operation::Android(o) => o.operation_id = id(4),
            Operation::Ios(o) => o.operation_id = id(4),
            _ => unreachable!(),
        };
        assert!(!wrong.valid_for(&s.review));
        let mut over = value.clone();
        match &mut over {
            Operation::Android(o) => o
                .result
                .as_mut()
                .unwrap()
                .candidate
                .as_mut()
                .unwrap()
                .source_tree
                .reserve(android::REPORT_LIMIT),
            Operation::Ios(o) => o
                .result
                .as_mut()
                .unwrap()
                .candidate
                .as_mut()
                .unwrap()
                .source_tree
                .reserve(ios::REPORT_LIMIT),
            _ => unreachable!(),
        };
        assert!(over.valid_for(&s.review));
        assert!(over.compact().is_err());
        let bytes = match value {
            Operation::Android(o) => serde_json::to_vec(&o).unwrap(),
            Operation::Ios(o) => serde_json::to_vec(&o).unwrap(),
            _ => unreachable!(),
        };
        assert!(
            bytes.len()
                < match family {
                    Family::AndroidInspect => android::REPORT_LIMIT,
                    Family::IosArchive => ios::REPORT_LIMIT,
                }
        );
    }
}
#[test]
fn candidate_and_ordinary_requests_share_all32_retained_rows_and_cross_family_refuses() {
    let f = Fixture::new();
    let read = Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(60),
    ));
    for n in 0..LIMIT {
        let family = if n % 2 == 0 {
            Family::AndroidInspect
        } else {
            Family::IosArchive
        };
        let s = if n % 4 < 2 {
            scope(&f, family, read.clone())
        } else {
            f.scope(family)
        };
        f.inbox.allow(s).unwrap();
        let p = f.request((n + 3) as u8);
        f.inbox.prepare(family, p.clone(), &f.point).unwrap();
        let other = if family == Family::AndroidInspect {
            Family::IosArchive
        } else {
            Family::AndroidInspect
        };
        assert!(f.inbox.query(other, &p.query(), true).is_err());
        let cancelled = f.inbox.query(family, &p.query(), true).unwrap();
        assert!(cancelled.operation.is_none());
        assert!(f.inbox.claim(family).unwrap().is_none());
        assert_eq!(
            f.inbox.prepare(family, p, &f.point).unwrap().request_state,
            cancelled.request_state
        );
    }
    assert_eq!(f.inbox.book.lock().unwrap().entries.len(), LIMIT);
    for family in [Family::AndroidInspect, Family::IosArchive] {
        assert_eq!(f.inbox.entries(family).unwrap().len(), 16);
        assert!(matches!(
            f.inbox.allow(scope(&f, family, read.clone())),
            Err(Error::Busy)
        ));
    }
}
