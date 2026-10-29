use super::*;
use std::time::Duration;

#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn installed_cli_native_progress_data()->Arc<installed_progress::ApplyProgress> {
    use installed_progress::{Boundary,Control,Job,Point};
    let (_doc,inbox,input)=setup();let prepare=prepared(&inbox,&input);let entry=prepare.entry();
    let before=entry.status().unwrap();let data=entry.installed_cli_progress();
    assert_eq!(serde_json::to_value(data.snapshot()).unwrap(),serde_json::json!({"mask":0,"controlMask":0,"firstError":null}));
    data.job(Job::Publisher,Point::Registered);data.job(Job::Publisher,Point::Entered);
    data.job(Job::Publisher,Point::JoinReturned);data.job(Job::Publisher,Point::Entered);
    data.boundary(Boundary::StartupEntered);data.first_error(InstalledNativeFailure::Busy);
    data.first_error(InstalledNativeFailure::Other);
    data.control(Control::RuntimeResolveRequested);data.control(Control::RuntimeResolveRequested);
    assert_eq!(serde_json::to_value(data.snapshot()).unwrap(),serde_json::json!({"mask":(1u32<<24)|7,"controlMask":1u32<<6,"firstError":"busy"}));
    assert_eq!(entry.status().unwrap(),before);
    let mut foreign=input.origin.clone();foreign.request_id=id('f');let mut facts=None;
    assert!(!entry.installed_cli_returned_observed(&foreign,Family::Index,Phase::Apply,before.revision,&mut facts));
    assert!(facts.is_none());
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Apply,before.revision,&mut facts));
    assert_eq!(entry.status().unwrap(),before);
    // DATA remains readable while the original Entry mutex is held. No
    // native/Entry authority or second predicate is reachable through it.
    let _guard=entry.row.lock().unwrap();data.boundary(Boundary::HostTicketRequested);
    assert_eq!(serde_json::to_value(data.snapshot()).unwrap()["mask"],serde_json::json!((3u32<<24)|7));
    let earlier=data.snapshot();data.control(Control::SourceInspectRequested);
    assert_ne!(data.snapshot(),earlier);
    assert_eq!(serde_json::to_value(earlier).unwrap()["controlMask"],serde_json::json!(1u32<<6));
    use Control::*;
    let points=[StartupReturnedOk,InspectionRegistered,InspectionWorkerReleased,GitInspectionEntered,
        AclArmRequested,AclArmReturned,RuntimeResolveRequested,RuntimeResolveReturned,SourceInspectRequested,
        SourceInspectReturned,RequestStoredCurrentOk,InspectionJoinReturned,InspectionOkAccepted,
        ChildSpawnRequested,ChildSpawnReturned,RequestWriteReturned,ReadyParsed,WriterReadyReturned,
        WriterPostSent,PostReceived,NativePostRequested,NativePostReturned,SourcePostRequested,
        SourcePostReturned,PostJoinReturned,PostAckRequested,WriterPostReplyReturned,GoClaimRequested,
        GoClaimReturnedOk,GoWriteReturned,CandidateRowValidated,CandidateReceiverReturned];
    let all=installed_progress::ApplyProgress::default();let mut expected=0u32;
    for (index,point) in points.into_iter().enumerate() {
        all.control(point);all.control(point);expected|=1u32<<index;
        assert_eq!(serde_json::to_value(all.snapshot()).unwrap(),serde_json::json!({"mask":0,"controlMask":expected,"firstError":null}));
    }
    assert_eq!(expected,u32::MAX);
    let jobs=[Job::Publisher,Job::Host,Job::Open,Job::Preparing,Job::Candidate,Job::Finish,Job::RetireUse,Job::FinishPublisher];
    let boundaries=[Boundary::StartupEntered,Boundary::HostTicketRequested,Boundary::HostTicketReturned,
        Boundary::ReadyHandoffRequested,Boundary::ReadyHandoffReturned,Boundary::FinalizeEntered,Boundary::RetireEntered,Boundary::OwnerArmed];
    let mut expected_mask=0u32;
    for (index,job) in jobs.into_iter().enumerate() {
        for (offset,point) in [Point::Registered,Point::Entered,Point::JoinReturned].into_iter().enumerate() {
            all.job(job,point);all.job(job,point);expected_mask|=1u32<<(3*index+offset);
            assert_eq!(serde_json::to_value(all.snapshot()).unwrap(),serde_json::json!({"mask":expected_mask,"controlMask":u32::MAX,"firstError":null}));
        }
    }
    for (index,boundary) in boundaries.into_iter().enumerate() {
        all.boundary(boundary);all.boundary(boundary);expected_mask|=1u32<<(24+index);
        assert_eq!(serde_json::to_value(all.snapshot()).unwrap(),serde_json::json!({"mask":expected_mask,"controlMask":u32::MAX,"firstError":null}));
    }
    assert_eq!(expected_mask,u32::MAX);
    installed_progress::snapshot_pair_contract_data();
    data
}

#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn installed_cli_wait_data_facts(apply: bool) -> InstalledCliReturnFacts {
    // Actual memory-only Entry sampling through the original predicate. These
    // synthetic link callbacks never execute a native or installed operation.
    let (_doc,inbox,input)=setup();let prepare=prepared(&inbox,&input);
    let entry=prepare.entry();
    if apply {
        let (_,revision,_,_)=entry.claim_history().unwrap().unwrap();
        entry.history_returned(revision,Ok(())).unwrap();
        inbox.start(&start(&input)).unwrap();
        let mut claim=inbox.claim().unwrap().unwrap();let link=claim.link().unwrap();
        link.arm("git-local-2").unwrap();claim.returned(Ok(()));
    }
    let before=entry.status().unwrap();let mut facts=None;
    let phase=if apply {Phase::Apply}else{Phase::Prepare};
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,phase,before.revision,&mut facts));
    assert_eq!(entry.status().unwrap(),before);
    let actual=facts.unwrap();
    assert!(actual.prepare_joined && !actual.apply_joined && !actual.claimed && !actual.history_failed);
    assert_eq!(actual.state,if apply {p::State::Applying}else{p::State::Prepared});
    assert!(!actual.history_acknowledged); // Neither missing return is admitted.
    let mut foreign=input.origin.clone();foreign.request_id=id('f');facts=None;
    assert!(!entry.installed_cli_returned_observed(&foreign,Family::Index,phase,before.revision,&mut facts));
    assert!(facts.is_none());
    let raw=serde_json::to_string(&actual).unwrap();
    assert!(raw.len()<1024 && !raw.contains("requestId") && !raw.contains("projectId") && !raw.contains("git-local-"));
    actual
}

#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn installed_unknown_transition_is_first_original_and_cannot_grant_return() {
    assert_installed_unknown_transition_contract();
}
#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn assert_installed_unknown_transition_contract() {
    // Inert rows and synthetic callbacks, never an actual native retirement.
    for origin in [UnknownOrigin::Unspecified, UnknownOrigin::NativeRetirementUnknown,
        UnknownOrigin::NativeRetirementInvalid, UnknownOrigin::DuplicatePrepareRetirement,
        UnknownOrigin::DuplicateApplyRetirement, UnknownOrigin::ClaimPhaseMismatch,
        UnknownOrigin::ClaimOkUnarmed, UnknownOrigin::ClaimReturnedUnknown,
        UnknownOrigin::ClaimReturnedArmedError, UnknownOrigin::ClaimRemoteReturnUnknown,
        UnknownOrigin::ClaimDropped] {
        let (_doc,inbox,input)=setup();
        let link=prepared(&inbox,&input);let entry=link.entry();
        let before=entry.status().unwrap();
        entry.unknown_from(origin,Some(Phase::Prepare));
        let first=entry.status().unwrap();
        assert_eq!(first.state,p::State::Unknown);
        assert_eq!(first.settlement,Settlement::Unknown);
        assert_eq!(first.revision,before.revision+1);
        entry.unknown_from(UnknownOrigin::ClaimDropped,Some(Phase::Apply));
        assert_eq!(entry.status().unwrap(),first);
        let mut facts=None;
        assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,first.revision,&mut facts));
        assert_eq!(facts.unwrap().unknown_transition,Some(InstalledUnknownTransition {origin,phase:Some(Phase::Prepare)}));
        let mut foreign=input.origin.clone();foreign.request_id=id('f');facts=None;
        assert!(!entry.installed_cli_returned_observed(&foreign,Family::Index,Phase::Prepare,first.revision,&mut facts));
        assert!(facts.is_none());
    }
    // Real original Entry branch calls distinguish callback, caller and drop.
    for (case,expected) in [(0,UnknownOrigin::NativeRetirementUnknown),
        (1,UnknownOrigin::DuplicatePrepareRetirement),(2,UnknownOrigin::ClaimReturnedArmedError),
        (3,UnknownOrigin::ClaimDropped),(4,UnknownOrigin::ClaimOkUnarmed),
        (5,UnknownOrigin::ClaimReturnedUnknown)] {
        let (_doc,inbox,input)=setup();inbox.prepare(input.clone()).unwrap();
        let mut claim=inbox.claim().unwrap().unwrap();
        let entry=claim.entry().clone();
        match case {
            0|1=>{let link=claim.link().unwrap();link.arm("git-local-1").unwrap();claim.returned(Ok(()));
                if case==1 {link.retired(OperationState::Succeeded);link.retired(OperationState::Succeeded);}
                else {link.retired(OperationState::Unknown);}},
            2=>{let link=claim.link().unwrap();link.arm("git-local-1").unwrap();claim.returned(Err(Error::Conflict));},
            3=>drop(claim),4=>claim.returned(Ok(())),_=>claim.returned(Err(Error::StateUnknown)),
        }
        assert_eq!(entry.row.lock().unwrap().installed_transitions.unknown,
            Some(InstalledUnknownTransition {origin:expected,phase:Some(Phase::Prepare)}));
        assert_eq!(entry.status().unwrap().state,p::State::Unknown);
    }
}

#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn installed_apply_rejection_and_native_failure_are_first_closed_data_only() {
    assert_installed_apply_failure_contract();
}
#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn assert_installed_apply_failure_contract() {
    crate::saved_command_owner::AndroidRegistrationControl::assert_installed_git_epoch_rejection_data();
    let (_doc,inbox,input)=setup();let prepare=prepared(&inbox,&input);
    prepare.installed_apply_rejected(PrepareRejection::EditGuard);
    assert!(prepare.entry().row.lock().unwrap().installed_transitions.apply_rejection.is_none());
    inbox.start(&start(&input)).unwrap();
    let mut claim=inbox.claim().unwrap().unwrap();let apply=claim.link().unwrap();apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));let entry=apply.entry();let before=entry.status().unwrap();
    apply.installed_apply_rejected_with_epoch(PrepareRejection::PublisherFinished,Some(crate::error::InstalledGitEpochRejection::BookWouldBlock));
    apply.installed_apply_rejected_with_epoch(PrepareRejection::EpochRead,Some(crate::error::InstalledGitEpochRejection::OtherPublisherPending));
    assert!(entry.row.lock().unwrap().installed_transitions.apply_epoch_rejection.is_none());
    apply.installed_apply_rejected(PrepareRejection::EpochMismatch);
    apply.installed_native_failure(InstalledNativeFailure::ContextChanged);
    apply.installed_native_failure(InstalledNativeFailure::CleanupUnknown);
    assert_eq!(entry.status().unwrap(),before);
    let mut facts=None;
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Apply,before.revision,&mut facts));
    let actual=facts.unwrap();
    assert_eq!(actual.apply_rejection,Some(PrepareRejection::PublisherFinished));
    assert_eq!(actual.native_failure,Some(InstalledNativeFailureFacts {category:InstalledNativeFailure::ContextChanged,phase:Phase::Apply}));
    assert!(actual.prepare_rejection.is_none() && actual.unknown_transition.is_none() && !actual.apply_joined);
    let raw=serde_json::to_string(&actual).unwrap();
    assert!(raw.len()<1024 && !raw.contains("requestId") && !raw.contains("projectId") && !raw.contains("git-local-2"));
    assert_eq!(InstalledNativeFailure::from_code("CANARY_PRIVATE"),InstalledNativeFailure::Other);
    assert_eq!(InstalledNativeFailure::from_code("busy"),InstalledNativeFailure::Busy);
    drop(apply);
    let (_doc,inbox,input)=setup();let _prepare=prepared(&inbox,&input);
    inbox.start(&start(&input)).unwrap();let mut claim=inbox.claim().unwrap().unwrap();
    let apply=claim.link().unwrap();apply.arm("git-local-2").unwrap();claim.returned(Ok(()));
    let entry=apply.entry();let before=entry.status().unwrap();
    apply.installed_apply_rejected_with_epoch(PrepareRejection::EpochRead,Some(crate::error::InstalledGitEpochRejection::BookWouldBlock));
    apply.installed_apply_rejected_with_epoch(PrepareRejection::EpochRead,Some(crate::error::InstalledGitEpochRejection::OtherPublisherPending));
    let mut facts=None;
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Apply,before.revision,&mut facts));
    let actual=facts.unwrap();
    assert_eq!(actual.apply_rejection,Some(PrepareRejection::EpochRead));
    assert_eq!(actual.apply_epoch_rejection,Some(crate::error::InstalledGitEpochRejection::BookWouldBlock));
    assert_eq!(serde_json::to_value(actual).unwrap()["applyEpochRejection"],serde_json::json!("book-would-block"));
    assert_eq!(entry.status().unwrap(),before);
}

#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn installed_return_diagnostics_keep_exact_history_and_caller_requirements() {
    // Inert request DATA and synthetic native-link returns, no installed result.
    let (_doc,inbox,input)=setup();
    let link=prepared(&inbox,&input);
    let entry=link.entry();
    let revision=entry.status().unwrap().revision;
    let mut facts=None;
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,revision,&mut facts));
    let first=facts.unwrap();
    assert!(first.prepare_joined && !first.claimed && !first.history_acknowledged && first.review_present);
    let raw=serde_json::to_string(&first).unwrap();
    assert!(raw.len()<1024 && !raw.contains("git-index") && !raw.contains("requestId") && !raw.contains("projectId"));
    let (_,history_revision,_,_)=entry.claim_history().unwrap().unwrap();
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,revision,&mut facts));
    assert!(facts.unwrap().history_claimed);
    entry.history_returned(history_revision,Ok(())).unwrap();
    assert!(entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,revision,&mut facts));
    let mut foreign=input.origin.clone();foreign.request_id=id('d');facts=None;
    assert!(!entry.installed_cli_returned_observed(&foreign,Family::Index,Phase::Prepare,revision,&mut facts));
    assert!(facts.is_none());
    assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,revision+1,&mut facts));
    assert!(!facts.unwrap().revision_matched);
}
#[cfg(all(debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn installed_prepare_rejection_is_first_original_data_and_never_a_review_or_return() {
    for rejection in [PrepareRejection::EditGuard, PrepareRejection::OriginalGate, PrepareRejection::FetchGate,
        PrepareRejection::PushGate, PrepareRejection::RequestGate, PrepareRejection::PublisherLock,
        PrepareRejection::PublisherFinished, PrepareRejection::PublisherMissing, PrepareRejection::EpochRead,
        PrepareRejection::EpochMismatch, PrepareRejection::EditStamp, PrepareRejection::NativeProject,
        PrepareRejection::PostProject, PrepareRejection::NativeState, PrepareRejection::ReviewClock,
        PrepareRejection::ReviewDecode, PrepareRejection::SelectionReview, PrepareRejection::EntryReady] {
        let (_doc,inbox,input)=setup();
        inbox.prepare(input.clone()).unwrap();
        let mut claim=inbox.claim().unwrap().unwrap();
        let link=claim.link().unwrap();link.arm("git-local-1").unwrap();
        claim.returned(Ok(()));link.retired(OperationState::Succeeded);
        let entry=link.entry();let before=entry.status().unwrap();
        link.installed_prepare_rejected(rejection);
        link.installed_prepare_rejected(PrepareRejection::EntryReady);
        assert_eq!(entry.status().unwrap(),before);
        link.no_review();
        let status=entry.status().unwrap();
        assert_eq!(status.state,p::State::Cancelled);
        assert_eq!(status.reason,Some(p::Reason::ContextChanged));
        let mut facts=None;
        assert!(!entry.installed_cli_returned_observed(&input.origin,Family::Index,Phase::Prepare,status.revision,&mut facts));
        let actual=facts.unwrap();
        assert_eq!(actual.prepare_rejection,Some(rejection));
        assert!(actual.prepare_joined && !actual.review_present && !actual.stopped);
        let raw=serde_json::to_string(&actual).unwrap();
        assert!(raw.len()<1024 && !raw.contains("requestId") && !raw.contains("projectId"));
    }
}
fn id(v: char) -> Id {
    Id::parse(&v.to_string().repeat(32)).unwrap()
}
fn scope(document: &Arc<()>) -> Arc<NativeScope> {
    let (changes, _) = tokio::sync::watch::channel(0);
    Arc::new(NativeScope {
        project_id: id('a'),
        runtime_id: "project-1".into(),
        root: "/inert/git-index".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: Some("git-read-1".into()),
        document: Arc::downgrade(document),
        selection: p::Selection::new(p::Action::Stage, "d".repeat(64), vec!["app/a.txt".into()])
            .unwrap().into(),
        commit: None,
        changes,
    })
}
fn setup() -> (Arc<()>, Inbox, p::Prepare) {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let access = inbox.allow(scope(&doc)).unwrap();
    let input = p::Prepare {
        origin: p::Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
        },
        grant_id: access.grant_id.unwrap(),
    };
    (doc, inbox, input)
}
fn review() -> p::Review {
    p::Review {
        review_id: "git-local-1-review".into(),
        expected_index: "e".repeat(64),
        review_digest: "f".repeat(64),
        document_revision: 1,
        registration_generation: 1,
    }
}
fn prepared(inbox: &Inbox, input: &p::Prepare) -> Arc<NativeLink> {
    inbox.prepare(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    link.retired(OperationState::Succeeded);
    assert!(link
        .ready(review(), Instant::now() + Duration::from_secs(300))
        .unwrap());
    link
}
fn start(input: &p::Prepare) -> p::Start {
    p::Start {
        origin: input.origin.clone(),
        prepare_operation_id: "git-local-1".into(),
        review_id: "git-local-1-review".into(),
    }
}
#[test]
fn catalogue_discovery_preserves_pending_and_unknown_without_expiring_or_claiming() {
    use crate::service_request_catalogue::AdditionalFamily;
    let (_doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let entry = inbox.book.lock().unwrap().entries[0].clone();
    entry.row.lock().unwrap().lease.as_ref().unwrap().revoked.store(true, Ordering::Release);
    let before = entry.row.lock().unwrap().status.clone();
    let rows = inbox.catalogue_requests(&id('b'), &id('a')).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].family, AdditionalFamily::GitIndex);
    assert_eq!(rows[0].request_id, input.origin.request_id);
    assert_eq!(entry.row.lock().unwrap().status, before);
    assert!(entry.row.lock().unwrap().stop.is_none());
    entry.unknown();
    let unknown = entry.row.lock().unwrap().status.clone();
    assert_eq!(inbox.catalogue_requests(&id('b'), &id('a')).unwrap(), rows);
    assert_eq!(entry.row.lock().unwrap().status, unknown);
    assert!(inbox.catalogue_requests(&id('b'), &id('e')).unwrap().is_empty());
    assert_eq!(inbox.catalogue_requests(&id('e'), &id('a')), Err(Error::StateUnknown));
    inbox.close();
    assert_eq!(inbox.catalogue_requests(&id('b'), &id('a')), Err(Error::Unavailable));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = inbox.book.lock().unwrap();
        panic!("inert catalogue lock poison");
    }));
    assert!(panic.is_err());
    assert_eq!(inbox.catalogue_requests(&id('b'), &id('a')), Err(Error::StateUnknown));
}
#[test]
fn read_access_and_foreign_grant_or_instance_never_create_a_request() {
    let (_doc, inbox, input) = setup();
    let empty = Inbox::new(id('b'));
    assert_eq!(
        empty.prepare(input.clone()).unwrap_err(),
        Error::AccessDenied
    );
    for which in 0..3 {
        let mut v = input.clone();
        match which {
            0 => v.origin.project_id = id('e'),
            1 => v.origin.service_instance = id('e'),
            _ => v.grant_id = id('e'),
        };
        assert!(inbox.prepare(v).is_err());
    }
    assert!(inbox.entries().unwrap().is_empty());
}
#[test]
fn duplicate_exact_request_observes_without_consuming_another_native_claim() {
    let (_doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let mut changed = input.clone();
    changed.grant_id = id('f');
    assert_eq!(inbox.prepare(changed).unwrap_err(), Error::Conflict);
    let first = inbox.prepare(input.clone()).unwrap();
    assert_eq!(first.state, p::State::Queued);
    assert_eq!(inbox.entries().unwrap().len(), 1);
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    assert_eq!(
        inbox
            .prepare(input)
            .unwrap()
            .prepare_operation_id
            .as_deref(),
        Some("git-local-1")
    );
    assert!(inbox.claim().unwrap().is_none());
}
#[test]
fn cancel_before_claim_is_known_nonentry_and_first_stop_is_idempotent() {
    let (_doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let first = inbox.query(&input.origin, true).unwrap();
    assert_eq!(first.state, p::State::Cancelled);
    let second = inbox.query(&input.origin, true).unwrap();
    assert_eq!(first, second);
    assert!(inbox.claim().unwrap().is_none());
}
#[test]
fn losing_original_claim_is_unknown_not_a_replay_or_an_available_slot() {
    let (doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    drop(inbox.claim().unwrap().unwrap());
    let v = inbox.query(&input.origin, false).unwrap();
    assert_eq!(v.settlement, Settlement::Unknown);
    assert!(inbox.allow(scope(&doc)).is_err());
    inbox.query(&input.origin, true).unwrap();
    assert_eq!(
        inbox.prepare(input).unwrap().settlement,
        Settlement::Unknown
    );
}
#[test]
fn prepare_receipt_does_not_make_ready_and_phase_ids_arm_before_dispatch() {
    let (_doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    assert!(link
        .ready(review(), Instant::now() + Duration::from_secs(30))
        .is_err());
    link.arm("git-local-1").unwrap();
    assert!(link.arm("git-local-2").is_err());
    claim.returned(Ok(()));
    link.retired(OperationState::Succeeded);
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().state,
        p::State::Preparing
    );
    assert!(inbox.start(&start(&input)).is_err());
    assert!(link
        .ready(review(), Instant::now() + Duration::from_secs(30))
        .unwrap());
    let mut wrong = start(&input);
    wrong.prepare_operation_id = "git-local-2".into();
    assert!(inbox.start(&wrong).is_err());
    inbox.start(&start(&input)).unwrap();
    let mut apply = inbox.claim().unwrap().unwrap();
    let next = apply.link().unwrap();
    assert!(next.same_request(&link));
    assert!(next.arm("git-local-1").is_err());
    next.arm("git-local-2").unwrap();
    apply.returned(Ok(()));
    link.review_removed();
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().state,
        p::State::Applying
    );
    next.retired(OperationState::Succeeded);
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().state,
        p::State::Finished
    );
    assert!(inbox.claim().unwrap().is_none());
}
#[test]
fn closed_original_review_cancels_only_unadmitted_apply() {
    let (_doc, inbox, input) = setup();
    let link = prepared(&inbox, &input);
    inbox.start(&start(&input)).unwrap();
    link.review_removed();
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().state,
        p::State::Cancelled
    );
    assert!(inbox.claim().unwrap().is_none());
}
#[test]
fn expiration_never_renews_grant_and_does_not_shorten_an_admitted_native_clock() {
    let (_doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let prepare = claim.link().unwrap();
    prepare.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    prepare
        .entry
        .expire(Instant::now() + Duration::from_secs(2000));
    prepare.current("git-local-1").unwrap();
    prepare.retired(OperationState::Succeeded);
    prepare
        .entry
        .expire(Instant::now() + Duration::from_secs(2000));
    assert!(!prepare
        .ready(review(), Instant::now() + Duration::from_secs(30))
        .unwrap());
    assert_eq!(prepare.entry.status().unwrap().state, p::State::Expired);
    let (_doc, inbox, input) = setup();
    let prior = prepared(&inbox, &input);
    inbox.start(&start(&input)).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let apply = claim.link().unwrap();
    apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    prior.review_removed();
    apply
        .entry
        .expire(Instant::now() + Duration::from_secs(2000));
    apply.current("git-local-2").unwrap();
    let at = Instant::now();
    apply.entry.cancel(p::Reason::PermissionRevoked, at);
    apply
        .entry
        .cancel(p::Reason::Expired, at + Duration::from_secs(20));
    assert_eq!(
        apply.entry.stop_at().unwrap(),
        Some((p::Reason::PermissionRevoked, at))
    );
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().settlement,
        Settlement::Pending
    );
    apply.retired(OperationState::Cancelled);
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().settlement,
        Settlement::Settled
    );
}
#[test]
fn expired_ready_waits_for_original_review_removal_but_cannot_start() {
    let (_doc, inbox, input) = setup();
    let link = prepared(&inbox, &input);
    link.entry.expire(Instant::now() + Duration::from_secs(901));
    assert!(inbox.start(&start(&input)).is_err());
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().settlement,
        Settlement::Pending
    );
    link.review_removed();
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().state,
        p::State::Expired
    );
}
#[test]
fn postarm_refusal_and_recovery_fence_cannot_become_known_nonentry() {
    let (doc, inbox, input) = setup();
    inbox.prepare(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Err(Error::Conflict));
    link.retired(OperationState::Failed);
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().settlement,
        Settlement::Unknown
    );
    assert!(inbox.allow(scope(&doc)).is_err());
    let (doc, inbox, input) = setup();
    let link = prepared(&inbox, &input);
    inbox.start(&start(&input)).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let apply = claim.link().unwrap();
    apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    link.review_removed();
    apply.retired(OperationState::RecoveryRequired);
    inbox.revoke().unwrap();
    let v = inbox.query(&input.origin, false).unwrap();
    assert_eq!(v.outcome, Some(OperationState::RecoveryRequired));
    assert_eq!(v.settlement, Settlement::Settled);
    assert!(inbox.allow(scope(&doc)).is_err());
}
#[test]
fn metadata_tombstones_drop_pathsets_without_eviction_and_history_does_not_settle() {
    let (doc, inbox, mut input) = setup();
    for i in 0..p::REQUEST_LIMIT {
        if i != 0 {
            input.grant_id = inbox.allow(scope(&doc)).unwrap().grant_id.unwrap();
            input.origin.request_id = Id::random().unwrap();
        }
        inbox.prepare(input.clone()).unwrap();
        inbox.query(&input.origin, true).unwrap();
    }
    assert_eq!(inbox.entries().unwrap().len(), p::REQUEST_LIMIT);
    assert!(inbox
        .entries()
        .unwrap()
        .iter()
        .all(|e| e.lock().unwrap().lease.is_none()));
    assert!(inbox.allow(scope(&doc)).is_err());
    let (_doc, inbox, input) = setup();
    let link = prepared(&inbox, &input);
    let (new, rev, _, _) = link.entry.claim_history().unwrap().unwrap();
    assert!(new);
    link.entry.history_returned(rev, Ok(())).unwrap();
    assert!(link.entry.status().unwrap().history_available);
    assert_eq!(link.entry.status().unwrap().settlement, Settlement::Pending);
    assert!(DOCUMENT_BACKING < 3 * 1024 * 1024);
}

#[cfg(all(debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn installed_cli_comparison_requires_each_original_and_exact_history_return() {
    // DATA calls only: no Document, native admission, files, child or socket.
    let (_doc,inbox,input)=setup();
    inbox.prepare(input.clone()).unwrap();
    let mut claim=inbox.claim().unwrap().unwrap();
    let link=claim.link().unwrap();link.arm("git-local-1").unwrap();
    let entry=&link.entry;
    link.retired(OperationState::Succeeded);
    link.ready(review(),Instant::now()+Duration::from_secs(300)).unwrap();
    let yes=||entry.installed_cli_returned(&input.origin,Family::Index,Phase::Prepare,entry.status().unwrap().revision);
    assert!(!yes()); // actual caller has not returned
    claim.returned(Ok(()));assert!(!yes());
    let h=entry.claim_history().unwrap().unwrap();assert!(!yes());
    entry.history_returned(h.1,Ok(())).unwrap();assert!(yes());
    assert!(!entry.installed_cli_returned(&input.origin,Family::Repository,Phase::Prepare,h.1));
    assert!(!entry.installed_cli_returned(&input.origin,Family::Index,Phase::Prepare,h.1-1));
    let mut foreign=input.origin.clone();foreign.request_id=id('f');
    assert!(!entry.installed_cli_returned(&foreign,Family::Index,Phase::Prepare,h.1));
    inbox.start(&start(&input)).unwrap();
    let mut claim=inbox.claim().unwrap().unwrap();let apply=claim.link().unwrap();apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    let finished=||entry.installed_cli_returned(&input.origin,Family::Index,Phase::Apply,entry.status().unwrap().revision);
    assert!(!finished()); // caller/history can never replace native retirement
    apply.retired(OperationState::Succeeded);assert!(!finished());
    let h=entry.claim_history().unwrap().unwrap();assert!(!finished());
    entry.history_returned(h.1,Ok(())).unwrap();assert!(finished());
    entry.cancel(p::Reason::UserCancelled,Instant::now());assert!(finished()); // late STOP only
    entry.unknown();assert!(!finished());
}
