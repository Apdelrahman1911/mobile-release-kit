//! Memory/correlation tests only. No Session, native receipt or join is faked.
use super::*;
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
    }
}
fn source() -> Source {
    Source {
        runtime_id: "runtime-1".into(),
        root: PathBuf::from("/not-opened/configuration-data"),
        device: 1,
        inode: 2,
        observation_revision: 7,
    }
}
fn setup() -> (Inbox, Arc<ReadPermission>) {
    (
        Inbox::new(id('1')),
        Arc::new(ReadPermission::new(
            Instant::now() + Duration::from_secs(300),
        )),
    )
}
#[test]
fn duplicate_read_is_same_data_and_other_request_cannot_replace_live_or_unknown_original() {
    let (book, read) = setup();
    let a = input('3');
    let first = book.read(a.clone(), source(), read.clone()).unwrap();
    assert_eq!(book.read(a.clone(), source(), read.clone()).unwrap(), first);
    let mut drift = a.clone();
    drift.expected_observation_revision = 8;
    assert_eq!(
        book.read(drift, source(), read.clone()).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        book.read(input('4'), source(), read.clone()).unwrap_err(),
        Error::Busy
    );
    let entry = book.entry(&a.origin).unwrap();
    assert!(entry.dispatch(Kind::Read).unwrap());
    entry.claim_open().unwrap();
    assert!(entry.claim_open().is_err());
    entry.dispatch_failed();
    assert_eq!(entry.status().unwrap().phase, p::Phase::Unknown);
    entry.cancel(Instant::now()).unwrap();
    assert_eq!(entry.status().unwrap().phase, p::Phase::Unknown);
    assert_eq!(
        book.read(input('4'), source(), read).unwrap_err(),
        Error::Busy
    );
}
#[test]
fn read_permission_never_supplies_an_original_preview_or_apply_grant() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read).unwrap();
    let e = book.entry(&a.origin).unwrap();
    let original = p::Original {
        session_id: id('4'),
        owner_generation: id('5'),
        revision: id('6'),
    };
    assert_eq!(
        e.prepare(p::Prepare {
            origin: a.origin.clone(),
            original: original.clone(),
            change: p::Change::Source {
                candidate_branch: "next".into(),
                production_branch: "production".into()
            }
        })
        .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        e.apply(p::Apply {
            origin: a.origin.clone(),
            original: original.clone(),
            plan_token: id('7'),
            reviewed: true
        })
        .unwrap_err(),
        Error::AccessDenied
    );
    assert_eq!(
        e.allow(
            &p::Allow {
                origin: a.origin,
                original,
                plan_token: id('7'),
                expected_native_status_revision: 1,
                consent_version: p::CONSENT.into()
            },
            Instant::now() + Duration::from_secs(60)
        )
        .unwrap_err(),
        Error::Conflict
    );
    assert!(e.history().unwrap().is_none());
    assert!(!e.bound(id('4').as_str(), id('5').as_str()));
}
#[test]
fn native_poll_retains_the_earliest_read_or_explicit_stop_without_a_renderer() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read.clone()).unwrap();
    let e = book.entry(&a.origin).unwrap();
    let first = Instant::now();
    read.revoke(first);
    e.cancel(first + Duration::from_secs(1)).unwrap();
    assert_eq!(
        e.stop_at(first + Duration::from_secs(5)).unwrap(),
        Some(first)
    );
    assert!(!e.live(first));
    assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
    assert!(e.dispatch(Kind::Read).is_ok_and(|b| !b));
    let expiry = Instant::now() - Duration::from_secs(1);
    let expired = Arc::new(ReadPermission::new(expiry));
    assert!(book.read(input('4'), source(), expired).is_err());
}
#[test]
fn exactly_thirty_two_cancelled_metadata_rows_stay_discoverable_without_history_eviction() {
    let (book, read) = setup();
    for n in 1..=p::REQUEST_LIMIT {
        let mut a = input('3');
        a.origin.request_id = Id::parse(&format!("{n:032x}")).unwrap();
        book.read(a.clone(), source(), read.clone()).unwrap();
        book.entry(&a.origin)
            .unwrap()
            .cancel(Instant::now())
            .unwrap();
    }
    assert_eq!(book.catalogue(&id('2')).unwrap().len(), 32);
    assert_eq!(
        book.read(input('f'), source(), read).unwrap_err(),
        Error::Busy
    );
    assert_eq!(book.entries().unwrap().len(), 32);
    for e in book.entries().unwrap() {
        assert!(e.history().unwrap().is_none());
    }
}
#[test]
fn exact_desktop_query_keeps_old_refusal_after_latest_row_without_fallback() {
    let (book, read) = setup();
    let old = input('3');
    book.read(old.clone(), source(), read.clone()).unwrap();
    let entry = book.entry(&old.origin).unwrap();
    entry.cancel(Instant::now()).unwrap(); // Actually unclaimed: no native receipt.
    let refused = entry.status().unwrap();
    assert_eq!(refused.phase, p::Phase::Refused);
    assert!(refused.original.is_none() && refused.result.is_none());

    let next = input('4');
    book.read(next.clone(), source(), read).unwrap();
    let latest = book.desktop().unwrap();
    assert_eq!(latest.request.as_ref().unwrap().origin, next.origin);
    let selected = book.desktop_request(&old.origin).unwrap();
    assert_eq!(selected.request, Some(refused));
    assert_eq!(selected.revision, latest.revision);
    assert_eq!(book.desktop().unwrap(), latest);
    for field in 0..3 {
        let mut wrong = old.origin.clone();
        match field {
            0 => wrong.service_instance = id('f'),
            1 => wrong.project_id = id('f'),
            _ => wrong.request_id = id('f'),
        }
        assert_eq!(book.desktop_request(&wrong).unwrap_err(), Error::Conflict);
    }

    let pending = book.entry(&next.origin).unwrap();
    assert!(pending.dispatch(Kind::Read).unwrap());
    pending.claim_open().unwrap();
    pending.dispatch_failed(); // A failed claimed dispatch is not known retirement.
    assert_eq!(
        book.desktop_request(&next.origin)
            .unwrap()
            .request
            .unwrap()
            .phase,
        p::Phase::Unknown
    );
    assert_eq!(
        book.desktop_request(&old.origin)
            .unwrap()
            .request
            .unwrap()
            .phase,
        p::Phase::Refused
    );
    assert!(pending.occupied().unwrap());
}
#[test]
fn wrong_origin_close_and_poison_cannot_rearm_a_prior_request() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read.clone()).unwrap();
    let mut bad = a.origin.clone();
    bad.project_id = id('f');
    assert!(book.entry(&bad).is_err());
    book.close(Instant::now());
    assert_eq!(
        book.read(a.clone(), source(), read.clone()).unwrap().phase,
        p::Phase::Refused
    );
    assert_eq!(
        book.read(input('4'), source(), read.clone()).unwrap_err(),
        Error::Unavailable
    );
    book.fence();
    assert_eq!(
        book.entry(&a.origin).unwrap().status().unwrap_err(),
        Error::StateUnknown
    );
}
#[test]
fn exhausted_original_status_or_publication_counter_fences_the_same_inbox() {
    for publication in [false, true] {
        let (book, read) = setup();
        let a = input('3');
        book.read(a.clone(), source(), read.clone()).unwrap();
        let entry = book.entry(&a.origin).unwrap();
        if publication {
            book.changes.send_replace(u32::MAX);
        } else {
            entry.row.lock().unwrap().status.revision = u32::MAX;
        }
        assert_eq!(entry.cancel(Instant::now()), Err(Error::StateUnknown));
        assert!(!entry.live(Instant::now()));
        assert_eq!(entry.status().unwrap_err(), Error::StateUnknown);
        assert_eq!(
            book.read(input('4'), source(), read).unwrap_err(),
            Error::Unavailable
        );
    }
}
