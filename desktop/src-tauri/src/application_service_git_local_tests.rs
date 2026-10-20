//! Actual idle Host/Doc/Publisher lock composition, no Store/native/Git IO.
use super::*;
use crate::{asset_session::DocumentBinding,bridge::DesktopBridge};
#[test]
fn git_local_publisher_host_wait_does_not_hold_document_status_or_stop() {
    let bridge=Arc::new(DesktopBridge::new("/never-opened-git-local-lock-test".into()));
    let document=DocumentBinding::new(bridge.clone());
    let host=bridge.application_service.clone();
    let (entered,arrived)=std::sync::mpsc::sync_channel(1);
    let (done,finished)=std::sync::mpsc::sync_channel(1);
    let locked=host.control.lock().unwrap();
    assert!(locked.store.is_none()&&locked.service.is_none());
    // Scoped thread ALWAYS joins after the original held Host lock is dropped,
    // including a failed assertion/report. No leaked worker or process runner.
    let (arrived,result,blocked)=std::thread::scope(|scope| {
        let worker=&document;
        let join=scope.spawn(move|| {let value=worker.git_local_publisher_segment_test(entered);let _=done.send(());value});
        let arrived=arrived.recv_timeout(Duration::from_secs(2));
        let (observed,observation)=std::sync::mpsc::sync_channel(1);
        let observing=&document;
        let probe=scope.spawn(move|| {
            let status=observing.git_local_status();
            let stopped=observing.git_local_cancel("no-such-original");
            let initial=status.operation.is_none()&&status.review.is_none()&&stopped.is_err();
            let _=observed.send(initial);
        });
        let initial=observation.recv_timeout(Duration::from_secs(2)).is_ok_and(|value|value);
        let blocked=finished.try_recv().is_err();
        // These are only unchanged initial public DATA; no native settlement.
        drop(locked);
        let probe=probe.join();
        let result=join.join();
        (arrived,result,(blocked,initial&&probe.is_ok()))
    });
    assert!(arrived.is_ok()&&blocked.0&&blocked.1);
    assert!(result.is_ok_and(|value|value.is_ok()));
    let state=host.control.lock().unwrap();
    assert!(state.store.is_none()&&state.service.is_none()&&state.pending.is_none());
}

// Only original Host memory admission with inert root DATA. Source probing,
// Store creation and positive NativeStateReady are deliberately never run.
fn unopened_ticket()->(ApplicationHost,Arc<NativeStateTicket>,NativeProject) {
    let host=ApplicationHost::new();
    let project=NativeProject {runtime_id:"project-1".into(),canonical_root:"/unopened-git-local-project".into(),
        device:1,inode:2,registration_generation:1,document_identity:Arc::new(()),input_revision:1};
    let root=RegisteredRoot {path:project.canonical_root.clone(),identity:asset_source::ProjectIdentity::Posix(
        asset_source::DirectoryIdentity::vault_original(1,2,0o40700,1001,1001))};
    host.reserve_native_state_location(Path::new("/unopened-git-local-state/dev.mobile-release-kit.desktop"),&[root]).unwrap();
    let ticket=Arc::new(host.begin_native_state_until(project.clone(),Instant::now()+Duration::from_secs(45)).unwrap());
    (host,ticket,project)
}
#[test]
fn git_local_busy_handoff_retains_exact_ticket_for_its_only_stop() {
    let (host,ticket,project)=unopened_ticket();let pointer=Arc::as_ptr(&ticket);
    {
        let locked=host.control.lock().unwrap();
        assert_eq!(host.finish_native_state_retained(&ticket,&project).err(),Some(Error::Busy));
        assert_eq!(locked.pending,Some(ticket.0.epoch));
    }
    assert_eq!(Arc::as_ptr(&ticket),pointer);
    assert_eq!(host.cancel_native_state_ticket(&ticket),Ok(()));
    assert_eq!(host.finish_native_state_retained(&ticket,&project).err(),Some(Error::AccessDenied));
    let state=host.control.lock().unwrap();
    assert!(state.pending.is_none()&&state.store.is_none()&&state.service.is_none());
}
#[test]
fn git_local_consumed_error_is_not_handoff_cleanup_or_another_admission() {
    let (host,ticket,project)=unopened_ticket();let epoch=ticket.0.epoch;
    // The unchanged Host body consumes pending before detecting no prepared
    // binding. The still-held ticket cannot make this a successful handoff.
    assert_eq!(host.finish_native_state_retained(&ticket,&project).err(),Some(Error::Conflict));
    assert_eq!(host.cancel_native_state_ticket(&ticket),Err(Error::Conflict));
    assert_eq!(host.finish_native_state_retained(&ticket,&project).err(),Some(Error::AccessDenied));
    let state=host.control.lock().unwrap();
    assert_eq!(state.epoch,epoch);
    assert!(state.pending.is_none()&&state.prepared.is_none()&&state.store.is_none()&&state.service.is_none());
}
