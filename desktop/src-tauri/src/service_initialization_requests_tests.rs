//! Actual compact methods only. These calls model DATA bookkeeping; no native
//! Session, filesystem result or resource-join receipt is supplied by a test.
use super::*;
use crate::service_configuration_requests::Inbox;
use std::{path::PathBuf, time::Duration};
fn id(n: usize) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn input(n: usize) -> p::Prepare {
    p::Prepare {
        origin: p::Query {
            service_instance: id(1),
            project_id: id(2),
            request_id: id(n),
        },
        expected_observation_revision: 7,
    }
}
fn source() -> Source {
    Source {
        runtime_id: "init-project".into(),
        root: PathBuf::from("/never-opened/init-requests"),
        device: 1,
        inode: 2,
        observation_revision: 7,
    }
}
fn setup() -> (Inbox, Arc<ReadPermission>, Arc<Entry>) {
    let book = Inbox::new(id(1));
    let read = Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(300),
    ));
    let q = input(3);
    book.initialization_prepare(q.clone(), source(), read.clone())
        .unwrap();
    let e = book.initialization_entry(&q.origin).unwrap();
    (book, read, e)
}
fn original() -> p::Original {
    p::Original {
        session_id: id(4),
        owner_generation: id(5),
        revision: id(6),
    }
}
fn review() -> p::Review {
    p::Review {
        plan_token: id(7),
        native_status_revision: 12,
        draft_revision: 7,
        baseline_generation: 3,
        file_count: 6,
        created_files: 6,
        preserved_files: 0,
        appended_files: 0,
        created_directories: 3,
        tooling_repository: "example/toolkit".into(),
        tooling_sha: "b".repeat(40),
    }
}
fn allow(e: &Entry) -> p::Allow {
    p::Allow {
        origin: e.input.origin.clone(),
        original: original(),
        plan_token: id(7),
        expected_native_status_revision: 12,
        expected_request_revision: e.status().unwrap().revision,
        consent_version: p::CONSENT.into(),
    }
}
fn reviewing_data(e: &Entry) {
    let mut r = e.lock().unwrap();
    r.status.original = Some(original());
    r.status.review = Some(review());
    r.status.phase = p::Phase::Reviewing;
    r.calls[0] = Returned::Returned;
    r.calls[1] = Returned::Returned;
    r.claimed = true;
}
#[test]
fn same_initialization_rows_and_all_return_cuts_remain_in_the_original_book() {
    let (book, read, e) = setup();
    let first = e.status().unwrap();
    assert_eq!(
        book.initialization_prepare(input(3), source(), read.clone())
            .unwrap(),
        first
    );
    assert!(book
        .initialization_prepare(input(8), source(), read.clone())
        .is_err());
    let mut changed = input(3);
    changed.expected_observation_revision = 8;
    assert!(book
        .initialization_prepare(changed, source(), read.clone())
        .is_err());
    assert!(e.history().unwrap().is_none());
    let call = e.caller(Kind::Open).unwrap();
    e.claim_open().unwrap();
    assert!(e.claim_open().is_err());
    assert!(!e.queued(Kind::Prepare).unwrap());
    assert!(e.history().unwrap().is_none());
    drop(call); // Actual unreturned Call guard, not a synthetic native return.
    assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
    assert!(e.history().unwrap().is_none()); // Cannot manufacture caller retirement.
    e.cancel(Instant::now()).unwrap();
    assert!(e.occupied().unwrap());
    assert!(book
        .initialization_prepare(input(8), source(), read)
        .is_err());
    assert!(e.status().unwrap().original.is_none());
}
#[test]
fn original_call_return_is_distinct_from_early_opened_or_prepared_data() {
    let (_book, _read, e) = setup();
    let marker = Arc::new(());
    let wake = Arc::new(Notify::new());
    let call = e.caller(Kind::Open).unwrap();
    e.claim_open().unwrap();
    e.bind(id(4), id(5), Arc::downgrade(&marker), &wake)
        .unwrap();
    e.opened(original()).unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::Opening);
    assert!(!e.queued(Kind::Prepare).unwrap());
    call.returned(true).unwrap();
    assert!(e.queued(Kind::Prepare).unwrap());
    let call = e.caller(Kind::Prepare).unwrap();
    e.consume(Kind::Prepare).unwrap();
    e.prepared(review()).unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::Preparing);
    assert!(e.reserve_allow(&allow(&e)).is_err());
    call.returned(true).unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::Reviewing);
    assert!(!e.status().unwrap().permission_available);
    assert!(e.history().unwrap().is_none());
    // This method DATA is not a native session/preview grant: no private Link
    // was made and no native finality is asserted by these bookkeeping calls.
    drop(marker);
    assert!(!e.bound(id(4).as_str(), id(5).as_str()));
}
#[test]
fn check_revision_is_consumed_before_wait_and_revoke_or_duplicate_cannot_rearm() {
    let (_book, _read, e) = setup();
    reviewing_data(&e);
    let args = allow(&e);
    let ticket = e.reserve_allow(&args).unwrap();
    assert!(e.reserve_allow(&args).is_err());
    e.cancel(Instant::now()).unwrap();
    assert!(e
        .allow(ticket, Instant::now() + Duration::from_secs(60))
        .is_err());
    assert!(!e.status().unwrap().permission_available);
    let (_book, _read, e) = setup();
    reviewing_data(&e);
    let old = allow(&e);
    e.cancel(Instant::now()).unwrap();
    assert!(e.reserve_allow(&old).is_err());
    let (_book, _read, e) = setup();
    reviewing_data(&e);
    let args = allow(&e);
    let ticket = e.reserve_allow(&args).unwrap();
    e.allow(ticket, Instant::now() + Duration::from_secs(30))
        .unwrap();
    let apply = p::Apply {
        origin: e.input.origin.clone(),
        original: original(),
        plan_token: id(7),
        reviewed: true,
    };
    let mut wrong = apply.clone();
    wrong.plan_token = id(9);
    assert!(e.apply(wrong).is_err());
    let first = e.apply(apply.clone()).unwrap();
    assert!(first.permission_consumed && !first.permission_available);
    assert_eq!(e.apply(apply.clone()).unwrap(), first);
    assert!(e.reserve_allow(&args).is_err());
    e.unknown();
    assert_eq!(e.apply(apply).unwrap().phase, p::Phase::Unknown);
    assert!(e.occupied().unwrap());
    assert!(!e.queued(Kind::Apply).unwrap_or(false));
}
#[test]
fn native_control_imports_earlier_read_even_after_stop_and_poison_is_absorbing() {
    let (_book, read, e) = setup();
    let first = Instant::now();
    e.cancel(first + Duration::from_secs(1)).unwrap();
    read.revoke(first);
    assert_eq!(
        e.stop_at(first + Duration::from_secs(2)).unwrap(),
        Some(first)
    );
    crate::service_version_reserve_requests::tests::poison_original_read(&read);
    assert_eq!(
        e.stop_at(first + Duration::from_secs(3)).unwrap_err(),
        Error::StateUnknown
    );
    assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
    assert!(e.occupied().unwrap());
    assert_eq!(e.history().unwrap().unwrap().2, Settlement::Unknown);
    e.history_returned(true).unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
    assert!(e.history().unwrap().is_none());
}
#[test]
fn known_unclaimed_refusal_waits_for_history_and_thirty_two_tombstones_are_not_evicted() {
    let book = Inbox::new(id(1));
    let read = Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(300),
    ));
    for n in 3..35 {
        let q = input(n);
        book.initialization_prepare(q.clone(), source(), read.clone())
            .unwrap();
        let e = book.initialization_entry(&q.origin).unwrap();
        e.cancel(Instant::now()).unwrap();
        assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
        assert!(e.occupied().unwrap());
        assert_eq!(e.history().unwrap().unwrap().1, OperationState::Cancelled);
        assert!(e.history().unwrap().is_none());
        e.history_returned(true).unwrap();
        let s = e.status().unwrap();
        assert_eq!(s.phase, p::Phase::Final);
        assert!(s.original.is_none());
        assert!(!s.result.unwrap().saved());
        assert!(!e.occupied().unwrap());
    }
    assert_eq!(book.initialization_entries().unwrap().len(), 32);
    assert_eq!(book.catalogue(&id(2)).unwrap().len(), 32);
    assert!(book
        .initialization_prepare(input(35), source(), read)
        .is_err());
    assert_eq!(
        book.initialization_desktop(Some(&input(3).origin))
            .unwrap()
            .request
            .unwrap()
            .origin,
        input(3).origin
    );
    let mut wrong = input(3).origin;
    wrong.project_id = id(40);
    assert!(book.initialization_desktop(Some(&wrong)).is_err());
}
#[test]
fn full_entry_capacity_is_bounded_without_borrowing_another_family_or_worker_slot() {
    let (_book, read, e) = setup();
    reviewing_data(&e);
    let fixed = std::mem::size_of::<Entry>()
        + std::mem::size_of::<Source>()
        + std::mem::size_of::<ReadPermission>()
        + std::mem::size_of::<Notify>();
    // Maximum actual root+runtime/coordinate heaps, every ID String (including
    // bind+apply+status copies), mutex/watch/Arc control and bookkeeping arrays.
    let heap = 4096 + 2 * 128 + 2 * (256 + 64) + 32 * 32 + 2048;
    assert!(fixed + heap <= ROW_BYTES);
    assert!(
        ROW_BYTES
            <= crate::service_configuration_protocol::STATUS_BYTES
                + 8192
                + std::mem::size_of::<crate::service_configuration_requests::Entry>()
    );
    let mut huge = source();
    huge.root = PathBuf::with_capacity(8192);
    huge.root.push("/not-opened");
    let (tx, _rx) = watch::channel(0);
    assert!(Entry::new(input(8), huge, read, Arc::new(AtomicBool::new(false)), tx).is_err());
    let mut too_much = review();
    too_much.tooling_repository.reserve_exact(4096);
    assert!(e.prepared(too_much).is_err());
    assert_eq!(e.status().unwrap().review.unwrap(), review());
}
#[test]
fn initialization_and_existing_configuration_share_exactly_thirty_two_retained_slots() {
    let book = Inbox::new(id(1));
    let read = Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(300),
    ));
    for n in 3..35 {
        let q = input(n);
        if n % 2 == 0 {
            book.read(
                crate::service_configuration_protocol::Read {
                    origin: q.origin.clone(),
                    expected_observation_revision: 7,
                },
                source(),
                read.clone(),
            )
            .unwrap();
            book.entry(&q.origin)
                .unwrap()
                .cancel(Instant::now())
                .unwrap();
        } else {
            book.initialization_prepare(q.clone(), source(), read.clone())
                .unwrap();
            let e = book.initialization_entry(&q.origin).unwrap();
            e.cancel(Instant::now()).unwrap();
            assert!(e.history().unwrap().is_some());
            e.history_returned(true).unwrap();
        }
    }
    let rows = book.catalogue(&id(2)).unwrap();
    assert_eq!(rows.len(), 32);
    assert_eq!(
        rows.iter()
            .filter(
                |r| r.family == crate::service_request_catalogue::AdditionalFamily::Initialization
            )
            .count(),
        16
    );
    assert!(book
        .initialization_prepare(input(40), source(), read.clone())
        .is_err());
    assert!(book
        .read(
            crate::service_configuration_protocol::Read {
                origin: input(41).origin,
                expected_observation_revision: 7
            },
            source(),
            read
        )
        .is_err());
}
