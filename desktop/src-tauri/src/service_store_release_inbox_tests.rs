//! SAME real Inbox/Entry methods, inert scopes only. No server or native IO.
use super::*;
use p::release::tests as data;

fn fixture(kind: p::Kind, platform: p::Platform, mode: p::release::Mode) -> Fixture {
    let mut f = Fixture::new();
    Arc::get_mut(&mut f.scope).unwrap().review = data::review(kind, platform, mode);
    f
}
fn finished(f: &Fixture) -> NativeData {
    let mut value = f.finished();
    value.result = Some(data::report(&f.scope.review));
    value
}

#[test]
fn store_release_all_modes_need_same_caller_native_and_history_returns() {
    for (kind, platform, mode) in data::cases() {
        for native_first in [true, false] {
            let f = fixture(kind, platform, mode);
            f.allow();
            let e = f.submit();
            let call = f.inbox.claim().unwrap().unwrap();
            if native_first {
                e.native(finished(&f));
            }
            assert!(e.pending());
            assert!(e.status().unwrap().result.is_none());
            call.returned();
            if !native_first {
                e.native(finished(&f));
            }
            assert!(e.pending());
            assert!(e.status().unwrap().result.is_none());
            let history = e.claim_history().unwrap().unwrap();
            assert!(e.pending());
            history.returned(Ok(())).unwrap();
            let status = e.status().unwrap();
            assert_eq!(status.state, p::State::Complete);
            assert!(!e.pending());
            assert!(status.result.unwrap().valid_for(&f.scope.review));
        }
    }
}

#[test]
fn store_release_same_request_reconnect_never_consumes_second_grant_or_mode() {
    for (kind, platform, mode) in data::cases() {
        let f = fixture(kind, platform, mode);
        f.allow();
        let e = f.submit();
        let replay = f.inbox.submit(f.input(), Instant::now()).unwrap();
        assert_eq!(replay.origin, *e.origin());
        assert_eq!(f.inbox.entries().unwrap().len(), 1);
        let mut another = f.input();
        another.origin.request_id = id('8');
        assert!(f.inbox.submit(another, Instant::now()).is_err());
        assert!(f
            .inbox
            .allow(Fixture::scope(&f.doc, &f.witness), id('9'))
            .is_err());
        let caller = f.inbox.claim().unwrap().unwrap();
        assert!(f.inbox.claim().unwrap().is_none());
        caller.returned();
        e.native(finished(&f));
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
    }
}

#[test]
fn store_release_cross_mode_result_or_lost_history_keeps_unknown_fence() {
    for lose_history in [false, true] {
        let f = fixture(
            p::Kind::Execute,
            p::Platform::Ios,
            p::release::Mode::ProductionSubmit,
        );
        f.allow();
        let e = f.submit();
        let call = f.inbox.claim().unwrap().unwrap();
        call.returned();
        if lose_history {
            e.native(finished(&f));
            drop(e.claim_history().unwrap().unwrap());
        } else {
            let mut n = finished(&f);
            n.result = Some(data::report(&data::review(
                p::Kind::Reconcile,
                p::Platform::Ios,
                p::release::Mode::ExternalReadiness,
            )));
            e.native(n);
        }
        e.native(finished(&f));
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
        assert!(e.status().unwrap().result.is_none());
        assert!(e.pending());
        assert!(f.inbox.can_allow().is_err());
    }
}

#[test]
fn store_release_earliest_read_revocation_is_not_renewed_by_mode_or_status() {
    let f = fixture(
        p::Kind::Reconcile,
        p::Platform::Android,
        p::release::Mode::RecoverySettlement,
    );
    f.allow();
    let e = f.submit();
    let at = e.submitted_at();
    e.cancel(p::Reason::UserCancelled, at + Duration::from_secs(2));
    f.scope.read.revoke(at + Duration::from_secs(1));
    assert_eq!(
        e.stop_at(at + Duration::from_secs(3)),
        Some(at + Duration::from_secs(1))
    );
    let first = f.scope.control.first().unwrap();
    let _ = e.status();
    e.cancel(p::Reason::Shutdown, at + Duration::from_secs(4));
    assert_eq!(f.scope.control.first().unwrap(), first);
    assert!(e.pending());
    assert!(f.inbox.can_allow().is_err());
}
