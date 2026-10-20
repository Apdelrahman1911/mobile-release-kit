//! Inert comparison cases for the SAME shared Prepare/Apply guard. These do
//! not create a native Git owner, a source receipt or a qualified execution.
use super::*;
use crate::{
    service_git_protocol as agent, service_git_requests as requests,
    service_protocol::{Id, OperationState},
};

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn links(document: &Arc<()>) -> (Arc<requests::NativeLink>, Arc<requests::NativeLink>) {
    let inbox = requests::Inbox::new(id('a'));
    let selection =
        agent::Selection::new(agent::Action::Stage, "b".repeat(64), vec!["app/a".into()]).unwrap();
    let scope = Arc::new(requests::NativeScope {
        project_id: id('c'),
        runtime_id: "project-1".into(),
        root: "/inert/not-opened".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 0,
        read_operation_id: "git-read-1".into(),
        document: Arc::downgrade(document),
        selection,
        commit: None,
        changes: tokio::sync::watch::channel(0).0,
    });
    let grant_id = inbox.allow(scope).unwrap().grant_id.unwrap();
    let origin = agent::Query {
        project_id: id('c'),
        service_instance: id('a'),
        request_id: id('d'),
    };
    inbox
        .prepare(agent::Prepare {
            origin: origin.clone(),
            grant_id,
        })
        .unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let prepare = claim.link().unwrap();
    prepare.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    // DATA injections exercise only the original pointer/phase predicate below.
    // Production can reach ready() only through actual native reconciliation.
    prepare.retired(OperationState::Succeeded);
    prepare
        .ready(
            agent::Review {
                review_id: "git-local-1-review".into(),
                expected_index: "e".repeat(64),
                review_digest: "f".repeat(64),
                document_revision: 1,
                registration_generation: 1,
            },
            Instant::now() + REVIEW,
        )
        .unwrap();
    inbox
        .start(&agent::Start {
            origin,
            prepare_operation_id: "git-local-1".into(),
            review_id: "git-local-1-review".into(),
        })
        .unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let apply = claim.link().unwrap();
    apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    (prepare, apply)
}

#[test]
fn shared_apply_requires_same_original_request_and_phase_not_matching_public_ids() {
    let document = Arc::new(());
    let (prepare, apply) = links(&document);
    let (foreign_prepare, foreign_apply) = links(&document); // Request/operation/review IDs deliberately equal.
    assert!(agent_review_matches(None, None)); // Ordinary GUI behavior unchanged.
    assert!(agent_review_matches(Some(&prepare), Some(&apply)));
    assert!(!agent_review_matches(Some(&prepare), None));
    assert!(!agent_review_matches(None, Some(&apply)));
    assert!(!agent_review_matches(Some(&prepare), Some(&prepare)));
    assert!(!agent_review_matches(Some(&prepare), Some(&foreign_apply)));
    assert!(!agent_review_matches(Some(&foreign_prepare), Some(&apply)));
}

#[test]
fn advisory_epoch_defers_own_publisher_transitions_but_preserves_joined_drift() {
    // The real memory-only control/publisher book has no Host, document,
    // native source, process or work admission. It can exercise exactly the
    // lock/epoch transitions that the existing finite publisher jobs perform.
    let control = Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default());
    let publisher = control
        .reserve(RegistrationPublisherKind::General, false)
        .unwrap();
    let slot = Mutex::new(PublisherSlot {
        value: Some(publisher),
        entered: false,
        joined: false,
        finished: false,
    });
    assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), Some(0));
    {
        let mut held = slot.lock().unwrap();
        assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), None);
        held.accept_original().unwrap();
        assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), None);
    }
    // The accept call returned, but the native parent's actual join/post
    // publication has not happened. The old epoch is not a STOP reason.
    assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), None);
    slot.lock().unwrap().joined = true;
    assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), Some(1));

    // A distinct actual publisher advances the original control epoch. Once
    // it returned, the watch supplies 2, never the expected own post-epoch 1.
    let mut foreign = control
        .reserve(RegistrationPublisherKind::General, false)
        .unwrap();
    assert!(agent_watch_epoch(&control, Some(&slot)).is_err());
    foreign
        .accept(crate::android_registration_app_protocol::Reason::ContextChanged)
        .unwrap();
    foreign.finish();
    assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), Some(2));
    {
        let mut held = slot.lock().unwrap();
        held.finished = true;
        finish_registration_publisher(held.value.take().unwrap());
    }
    assert_eq!(control.epoch().unwrap(), 2);
    // The last publisher job finished, not yet the Supervisor receipt. This
    // is advisory deferral, not an invented operation settlement.
    assert_eq!(agent_watch_epoch(&control, Some(&slot)).unwrap(), None);
    control.poisoned();
    assert!(agent_watch_epoch(&control, Some(&slot)).is_err());
}

#[test]
fn advisory_epoch_never_turns_poisoned_publisher_into_a_deferred_healthy_sample() {
    let control = Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default());
    let publisher = control
        .reserve(RegistrationPublisherKind::General, false)
        .unwrap();
    let slot = Mutex::new(PublisherSlot {
        value: Some(publisher),
        entered: false,
        joined: false,
        finished: false,
    });
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = slot.lock().unwrap();
        panic!("inert original publisher observer cut");
    }));
    assert!(unwind.is_err());
    assert!(agent_watch_epoch(&control, Some(&slot)).is_err());
    // Retire only the genuinely never-accepted memory publisher. The outer
    // poisoned slot is not cleared or granted any operational authority.
    let mut held = match slot.lock() {
        Err(error) => error.into_inner(),
        Ok(_) => panic!("the original publisher slot must stay poisoned"),
    };
    held.value.take().unwrap().reject();
    drop(held);
    assert!(agent_watch_epoch(&control, Some(&slot)).is_err());
}
