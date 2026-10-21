//! Actual in-memory Inbox/Entry/NativeLink ordering. No native receipt, task,
//! filesystem, signing input or build is manufactured by these DATA tests.
use super::*;
use crate::service_version_reserve_requests::ReadPermission;

fn selected(f: &Fixture, family: Family) -> (Prepare, Arc<NativeLink>, Claim) {
    f.inbox.allow(f.scope(family)).unwrap();
    let input = f.request(3);
    f.inbox.prepare(family, input.clone(), &f.point).unwrap();
    let claim = f.inbox.claim(family).unwrap().unwrap();
    let link = claim.entry().bind(family, id(4), id(5), 1,
        Instant::now() + Duration::from_secs(300)).unwrap();
    (input, link, claim)
}
fn start(input: &Prepare) -> Start { Start { origin: input.query(), operation_id: id(4), owner_generation: id(5) } }

#[test]
fn both_old_families_wait_for_original_prepare_and_history_before_start() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new(); let (input, link, claim) = selected(&f, family);
        let pending = link.entry().status().unwrap();
        assert_eq!(pending.request_state, RequestState::Preparing);
        assert!(pending.operation.is_none() && !pending.history_available);
        assert!(link.entry().claim_history().unwrap().is_none());
        assert!(f.inbox.start(family, &start(&input)).is_err());
        claim.returned(true);
        assert!(link.entry().status().unwrap().operation.is_none());
        let (_, original) = link.entry().claim_history().unwrap().unwrap();
        assert!(f.inbox.start(family, &start(&input)).is_err());
        link.entry().history_returned(original.status_revision(), Ok(())).unwrap();
        let ready = link.entry().status().unwrap();
        assert_eq!(ready.request_state, RequestState::OriginalAvailable);
        assert!(ready.history_available);
        f.inbox.start(family, &start(&input)).unwrap();
    }
}
#[test]
fn native_and_start_caller_orders_both_need_terminal_writer_ack_before_reuse() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        for native_first in [false, true] {
            let f = Fixture::new(); let (input, link, preparing) = selected(&f, family);
            preparing.returned(true); acknowledge(&link);
            f.inbox.start(family, &start(&input)).unwrap();
            let claim = f.inbox.claim(family).unwrap().unwrap();
            link.consume_start(family).unwrap();
            let final_value = terminal(&link);
            if native_first {
                link.publish(final_value).unwrap();
                assert!(link.entry().claim_history().unwrap().is_none());
                assert_eq!(link.entry().status().unwrap().operation.unwrap().state(), OperationState::Prepared);
                assert!(f.inbox.allow(f.scope(family)).is_err());
                claim.returned(true);
            } else { claim.returned(true); link.publish(final_value).unwrap(); }
            let (_, original) = link.entry().claim_history().unwrap().unwrap();
            assert!(f.inbox.allow(f.scope(family)).is_err());
            assert_ne!(link.entry().status().unwrap().operation.unwrap().settlement(), Settlement::Settled);
            link.entry().history_returned(original.status_revision(), Ok(())).unwrap();
            assert_eq!(link.entry().status().unwrap().operation.unwrap().settlement(), Settlement::Settled);
            f.inbox.allow(f.scope(family)).unwrap();
            assert_eq!(f.inbox.start(family, &start(&input)).unwrap().start_state, StartState::Consumed);
        }
    }
}
#[test]
fn lost_prepare_or_start_return_hides_old_success_immediately_and_late_native_cannot_heal() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        for lose_prepare in [false, true] {
            let f = Fixture::new(); let (input, link, preparing) = selected(&f, family);
            if lose_prepare { drop(preparing); }
            else {
                preparing.returned(true); acknowledge(&link);
                f.inbox.start(family, &start(&input)).unwrap();
                let claim = f.inbox.claim(family).unwrap().unwrap();
                link.consume_start(family).unwrap(); drop(claim);
            }
            let uncertain = link.entry().status().unwrap();
            assert_eq!(uncertain.request_state, RequestState::AdmissionUnknown);
            assert!(uncertain.operation.is_none() && !uncertain.history_available);
            link.publish(terminal(&link)).unwrap();
            assert!(link.entry().status().unwrap().operation.is_none());
            assert!(link.entry().claim_history().unwrap().is_none());
            assert!(f.inbox.allow(f.scope(family)).is_err());
        }
    }
}
#[test]
fn failed_or_lost_history_is_absorbing_and_keeps_exact_claim_not_last_ready() {
    for lost in [false, true] {
        let f = Fixture::new(); let (_, link, preparing) = selected(&f, Family::AndroidInspect);
        preparing.returned(true); acknowledge(&link); link.publish(terminal(&link)).unwrap();
        let (_, original) = link.entry().claim_history().unwrap().unwrap();
        let held = link.entry().publication.lock().unwrap().claim.clone().unwrap();
        if lost { link.entry().history_lost(); }
        else { assert!(link.entry().history_returned(original.status_revision(), Err(Error::StateUnknown)).is_err()); }
        let unknown = link.entry().status().unwrap();
        assert_eq!(unknown.request_state, RequestState::AdmissionUnknown);
        assert!(unknown.operation.is_none() && !unknown.history_available);
        assert!(link.entry().history_returned(original.status_revision(), Ok(())).is_err());
        assert!(Arc::ptr_eq(&held, link.entry().publication.lock().unwrap().claim.as_ref().unwrap()));
        assert!(f.inbox.allow(f.scope(Family::IosArchive)).is_err());
    }
}
fn signed_scope(f: &Fixture, family: Family, read: Arc<ReadPermission>) -> Arc<NativeScope> {
    let mut scope = f.scope(family); let value = Arc::get_mut(&mut scope).unwrap();
    value.read = Some(read);
    match &mut value.review {
        Review::Android(r) => {
            r.mode = android::Mode::SavedAndroidLocalUploadKeySign;
            r.upload_certificate_sha256 = Some("d".repeat(64));
            r.signing = Some(android::signed::Selection { mode: android::signed::SigningMode::LocalUploadKey,
                assignments: vec![android::signed::Assignment { kind: android::signed::Kind::AndroidKeystore,
                    record_id: id(8), record_revision: 1, context_revision: 1 }] });
        },
        Review::Ios(r) => { r.mode = ios::Mode::SavedIosSignedExport;
            r.signing = Some(ios::signed::Review { team_id: "ABCDE12345".into(), distribution_certificate_sha256: "d".repeat(64),
                firebase: false, project_read_token: false }); },
        Review::IosRecovery(_) => panic!("signed saved-build fixture only"),
    }
    scope
}
#[test]
fn signed_read_identity_and_earliest_stop_survive_consumption_without_changing_old_modes() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new(); let now = Instant::now();
        let read = Arc::new(ReadPermission::new(now + Duration::from_secs(60)));
        let scope = signed_scope(&f, family, read.clone());
        assert!(scope.valid() && scope.matches_read(&read));
        assert!(!scope.matches_read(&Arc::new(ReadPermission::new(read.end()))));
        let old = f.scope(family); assert!(old.valid() && old.read.is_none());
        f.inbox.allow(scope.clone()).unwrap(); let input = f.request(3);
        f.inbox.prepare(family, input.clone(), &f.point).unwrap();
        let preparing = f.inbox.claim(family).unwrap().unwrap();
        let link = preparing.entry().bind(family,id(4),id(5),1,now+Duration::from_secs(300)).unwrap();
        preparing.returned(true); acknowledge(&link);
        f.inbox.start(family,&start(&input)).unwrap();
        let starting = f.inbox.claim(family).unwrap().unwrap(); link.consume_start(family).unwrap(); starting.returned(true);
        assert_eq!(link.entry().control_poll(),Some(Duration::from_millis(5)));
        assert_eq!(link.entry().read_end(),Some(read.end()));
        assert_eq!(link.entry().read_stop(read.end()).unwrap(),Some(read.end()));
        link.entry().cancel(); let later = link.entry().stop_at(Instant::now()).unwrap();
        read.revoke(now); // Original READ has an earlier actual cut, even after first STOP.
        assert!(now <= later); assert_eq!(link.entry().stop_at(Instant::now()),Some(now));
        assert!(!scope.matches_read(&read)); assert!(link.entry().lease.scope.read.as_ref().is_some_and(|r|Arc::ptr_eq(r,&read)));
    }
}
