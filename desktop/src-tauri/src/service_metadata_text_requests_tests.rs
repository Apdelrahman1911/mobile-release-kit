//! Actual finite Entry/Inbox transitions with inert DATA callbacks. These tests
//! do not construct Session, NativeUse, file custody or a native join receipt.
use super::*;
use crate::service_configuration_requests::Inbox;
fn id(n: char) -> Id {
    Id::parse(&n.to_string().repeat(32)).unwrap()
}
fn input(n: char) -> p::Read {
    p::Read {
        origin: p::Query {
            service_instance: id('1'),
            project_id: id('2'),
            request_id: id(n),
        },
        expected_observation_revision: 7,
        platform: p::Platform::Android,
        locale: "en-US".into(),
    }
}
fn source() -> Source {
    Source {
        runtime_id: "project-a".into(),
        root: "/inert-not-opened/metadata".into(),
        device: 1,
        inode: 2,
        observation_revision: 7,
    }
}
fn setup() -> (Inbox, Arc<ReadPermission>, Arc<Entry>) {
    let book = Inbox::new(id('1'));
    let read = Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(300),
    ));
    book.metadata_read(input('3'), source(), read.clone())
        .unwrap();
    let e = book.metadata_entry(&input('3').origin).unwrap();
    (book, read, e)
}
fn observation() -> p::Observation {
    let ids = p::Platform::Android.ids();
    p::Observation {
        schema_version: 1,
        platform: p::Platform::Android,
        locale: "en-US".into(),
        metadata_root: "release/store".into(),
        observation_scope: "single-request-non-atomic".into(),
        baseline: p::Baseline {
            config: p::DigestData {
                byte_length: 2,
                sha256: p::sha(b"{}"),
            },
            fields: ids
                .iter()
                .map(|id| p::BaselineField::Absent { id: (*id).into() })
                .collect(),
        },
        fields: ids
            .iter()
            .map(|id| p::ObservedField::Absent {
                id: (*id).into(),
                path: format!("release/store/android/en-US/{id}"),
            })
            .collect(),
        assurance: p::Assurance {
            basis: "static-text".into(),
            project_code_executed: false,
            tools_probed: false,
            credentials_read: false,
            git_observed: false,
            store_contacted: false,
            writes_performed: false,
            release_readiness: "unknown".into(),
        },
    }
}
fn fields() -> p::Fields {
    p::Fields {
        platform: p::Platform::Android,
        fields: p::Platform::Android
            .ids()
            .iter()
            .map(|id| p::Field {
                id: (*id).into(),
                text: "Public text".into(),
            })
            .collect(),
    }
}
fn loaded(e: &Arc<Entry>) {
    assert!(e.dispatch(Kind::Read).unwrap());
    let call = e.caller(Kind::Read).unwrap();
    e.read_claim().unwrap();
    e.read_retired(Ok(observation()), false).unwrap();
    call.returned().unwrap();
}
fn reviewed(e: &Arc<Entry>) -> (Arc<()>, p::Allow) {
    loaded(e);
    e.prepare(p::Prepare {
        origin: input('3').origin,
        proposal: fields(),
    })
    .unwrap();
    assert!(e.dispatch(Kind::Open).unwrap());
    let call = e.caller(Kind::Open).unwrap();
    e.claim_open().unwrap();
    let marker = Arc::new(());
    e.bind(id('4'), id('5'), Arc::downgrade(&marker)).unwrap();
    let original = p::Original {
        session_id: id('4'),
        owner_generation: id('5'),
        revision: id('6'),
    };
    e.opened(original.clone()).unwrap();
    call.returned().unwrap();
    assert!(e.dispatch(Kind::Prepare).unwrap());
    let call = e.caller(Kind::Prepare).unwrap();
    e.consume(Kind::Prepare).unwrap();
    e.prepared(p::Review {
        plan_token: id('7'),
        native_status_revision: 5,
        proposal_sha256: fields().digest().unwrap(),
        files: fields()
            .fields
            .iter()
            .map(|f| p::File {
                id: f.id.clone(),
                action: "create".into(),
                before_bytes: None,
                after_bytes: f.text.len() as u32,
                after_sha256: p::sha(f.text.as_bytes()),
            })
            .collect(),
    })
    .unwrap();
    call.returned().unwrap();
    (
        marker,
        p::Allow {
            origin: input('3').origin,
            original,
            plan_token: id('7'),
            expected_native_status_revision: 5,
            consent_version: p::CONSENT.into(),
        },
    )
}
#[test]
fn load_visibility_waits_both_original_returns_in_either_order() {
    for native_first in [false, true] {
        let (_, _, e) = setup();
        e.dispatch(Kind::Read).unwrap();
        let call = e.caller(Kind::Read).unwrap();
        e.read_claim().unwrap();
        if native_first {
            e.read_retired(Ok(observation()), false).unwrap();
            assert_eq!(e.status().unwrap().phase, p::Phase::Reading);
            assert!(e.status().unwrap().observation.is_none());
            call.returned().unwrap();
        } else {
            call.returned().unwrap();
            assert_eq!(e.status().unwrap().phase, p::Phase::Reading);
            e.read_retired(Ok(observation()), false).unwrap();
        }
        assert_eq!(e.status().unwrap().phase, p::Phase::Loaded);
        assert!(e.status().unwrap().observation.is_some());
    }
}
#[test]
fn original_unknown_or_lost_caller_is_absorbing_and_cannot_release_the_shared_queue() {
    for lost in [false, true] {
        let (book, read, e) = setup();
        e.dispatch(Kind::Read).unwrap();
        let call = e.caller(Kind::Read).unwrap();
        e.read_claim().unwrap();
        e.read_retired(Ok(observation()), !lost).unwrap();
        if lost {
            drop(call)
        } else {
            e.dispatch_failed();
            call.returned().unwrap();
        }
        assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        e.cancel(Instant::now()).unwrap();
        e.dispatch_failed();
        assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
        assert!(book.metadata_read(input('4'), source(), read).is_err());
    }
}
#[test]
fn same_loaded_arc_and_prepare_digest_are_not_reloaded_or_retargeted() {
    let (_, _, e) = setup();
    loaded(&e);
    let original = e.load().unwrap();
    let input = p::Prepare {
        origin: input('3').origin,
        proposal: fields(),
    };
    let first = e.prepare(input.clone()).unwrap();
    assert_eq!(e.prepare(input.clone()).unwrap(), first);
    assert!(Arc::ptr_eq(&original, &e.load().unwrap()));
    let mut changed = input;
    changed.proposal.fields[0].text.push('!');
    assert!(e.prepare(changed).is_err());
    assert_eq!(e.status().unwrap(), first);
}
#[test]
fn exact_revoke_before_allow_and_read_expiry_never_rearm_the_review() {
    for revoke in [false, true] {
        let (_, read, e) = setup();
        let (_marker, allow) = reviewed(&e);
        let first = Instant::now();
        if revoke {
            e.cancel(first).unwrap()
        } else {
            read.revoke(first)
        }
        assert!(e.allow(&allow, first + Duration::from_secs(60)).is_err());
        assert_eq!(
            e.stop_at(first + Duration::from_secs(5)).unwrap(),
            Some(first)
        );
        assert!(!e.status().unwrap().permission_live);
        assert!(e
            .apply(p::Apply {
                origin: allow.origin,
                original: allow.original,
                plan_token: allow.plan_token,
                reviewed: true
            })
            .is_err());
    }
}
#[test]
fn apply_consumes_once_and_final_waits_return_while_cancelled_effect_is_not_saved() {
    for native_first in [false, true] {
        let (_, _, e) = setup();
        let (_marker, allow) = reviewed(&e);
        e.allow(&allow, Instant::now() + Duration::from_secs(60))
            .unwrap();
        let apply = p::Apply {
            origin: allow.origin,
            original: allow.original,
            plan_token: allow.plan_token,
            reviewed: true,
        };
        let first = e.apply(apply.clone()).unwrap();
        assert_eq!(e.apply(apply).unwrap(), first);
        e.dispatch(Kind::Apply).unwrap();
        let call = e.caller(Kind::Apply).unwrap();
        e.consume(Kind::Apply).unwrap();
        assert!(!e.dispatch(Kind::Apply).unwrap());
        e.cancel(Instant::now()).unwrap();
        let result = p::Final {
            effect: p::Effect::Committed,
            journal: p::Journal::Clean,
            cancelled: true,
            apply_submitted: true,
        };
        if native_first {
            e.retired(Some(result)).unwrap();
            assert_ne!(e.status().unwrap().phase, p::Phase::Final);
            call.returned().unwrap()
        } else {
            call.returned().unwrap();
            assert_ne!(e.status().unwrap().phase, p::Phase::Final);
            e.retired(Some(result)).unwrap()
        }
        let s = e.status().unwrap();
        assert_eq!(s.phase, p::Phase::Final);
        assert!(!s.result.unwrap().saved());
        let retained = e.lock().unwrap();
        assert!(retained.load.is_none() && retained.proposal.is_none());
    }
}
#[test]
fn same_thirty_two_combined_rows_have_closed_family_ids_and_original_query_after_coalescing() {
    let (book, read, e) = setup();
    let old = e.input().origin.clone();
    assert!(book.entry(&old).is_err());
    e.cancel(Instant::now()).unwrap();
    for n in 4..35 {
        let q = p::Query {
            service_instance: id('1'),
            project_id: id('2'),
            request_id: Id::parse(&format!("{n:032x}")).unwrap(),
        };
        if n % 2 == 0 {
            book.read(
                crate::service_configuration_protocol::Read {
                    origin: q.clone(),
                    expected_observation_revision: 7,
                },
                source(),
                read.clone(),
            )
            .unwrap();
            assert!(book.metadata_entry(&q).is_err());
            book.entry(&q).unwrap().cancel(Instant::now()).unwrap();
        } else {
            let mut i = input('3');
            i.origin = q.clone();
            book.metadata_read(i, source(), read.clone()).unwrap();
            assert!(book.entry(&q).is_err());
            book.metadata_entry(&q)
                .unwrap()
                .cancel(Instant::now())
                .unwrap();
        }
    }
    assert_eq!(book.catalogue(&id('2')).unwrap().len(), 32);
    assert_eq!(
        book.metadata_desktop(Some(&old))
            .unwrap()
            .request
            .unwrap()
            .origin,
        old
    );
    assert!(book.metadata_read(input('f'), source(), read).is_err());
    assert!(book.catalogue(&id('f')).unwrap().is_empty());
}
#[test]
fn public_load_lifetime_ends_at_original_read_stop_not_a_later_status() {
    let (_, read, e) = setup();
    loaded(&e);
    let first = e.load().unwrap();
    read.revoke(Instant::now());
    assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
    assert!(e.status().unwrap().observation.is_none());
    assert!(e.load().is_err());
    assert!(e.lock().unwrap().load.is_none());
    assert_eq!(Arc::strong_count(&first), 1);
}
