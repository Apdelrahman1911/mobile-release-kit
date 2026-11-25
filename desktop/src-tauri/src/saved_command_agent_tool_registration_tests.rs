//! Actual original Condvar/Control test, not Source/Review/native-join authority.
use super::*;
#[test]
fn quiet_read_revocation_interrupts_original_registration_wait_without_relay() {
    let at = Instant::now();
    let doc = Arc::new(());
    let id = |c: char| Id::parse(&c.to_string().repeat(32)).unwrap();
    let link = req::NativeLink::new(Arc::new(req::NativeScope {
        project_id: id('1'),
        runtime_id: "p1".into(),
        review_id: id('2'),
        review: p::Review {
            kind: p::Kind::InspectPickedSources,
            platform: p::Platform::Android,
            draft_revision: 1,
            baseline_generation: 1,
            prepared: None,
            sources: Some(p::Sources {
                registration_generation: 0,
                source_generation: 0,
                review_id: None,
            }),
            acquisition: None,
        },
        root: "/not-opened".into(),
        device: 1,
        inode: 2,
        observation_revision: 1,
        saved_config: None,
        expires: at + Duration::from_secs(5),
        read: Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                at + Duration::from_secs(5),
            ),
        ),
        document: Arc::downgrade(&doc),
        control: req::Control::new(),
        retired: AtomicBool::new(false),
        changes: watch::channel(0).0,
    }));
    let (slot, control, cohort, gate) = super::super::lifecycle_book_tests::control_for_agent(
        at,
        ControlLane::Sources,
        Some(link.clone()),
    );
    std::thread::scope(|scope| {
        let publisher = slot.reserve(PublisherKind::General, false).unwrap();
        let (sent, returned) = std::sync::mpsc::sync_channel(1);
        let gate = &gate;
        let worker = scope.spawn(move || {
            let result = gate.work();
            let _ = sent.send(result);
        });
        let end = Instant::now() + Duration::from_secs(2);
        while slot.wait_entries.load(Ordering::SeqCst) == 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        let waited = slot.wait_entries.load(Ordering::SeqCst) > 0;
        // Only the READ facet changes: no publisher resolution/Condvar notification.
        link.scope().read.revoke(at);
        let result = returned.recv_timeout(Duration::from_secs(2));
        // Resolve the test-owned publisher before join/assert even on a regression;
        // do not leave a worker blocked until the original 300-second endpoint.
        publisher.reject();
        worker.join().unwrap();
        assert!(waited);
        assert_eq!(result.unwrap(), Err((wire::Reason::Cancelled, at)));
    });
    assert_eq!(control.failure(), Some((wire::Reason::Cancelled, at)));
    assert_eq!(control.work, at + WORK);
    assert_eq!(control.hard, at + HARD);
    drop(cohort);
    assert!(!link.scope().retired.load(Ordering::Acquire));
}
