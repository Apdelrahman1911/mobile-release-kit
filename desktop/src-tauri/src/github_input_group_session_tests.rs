// State-transition DATA, not native settlement or remote authentication.
use super::*;
use wire::test_data as data;
fn completion(cleanup:wire::Settlement,finality:wire::Finality) -> wire::Completion {
    wire::Completion {journal:wire::Settlement::Unknown,cleanup,finality}
}
#[test]
fn later_journal_or_result_uncertainty_never_erases_an_observed_write() {
    for write in [wire::RemoteWrite::AcknowledgedCreated {status_code:201},wire::RemoteWrite::AcknowledgedUpdated {status_code:204},
        wire::RemoteWrite::ExplicitlyRejected {reason:wire::Reason::Forbidden}] {
        let mut state=State::new();let marker="a".repeat(32);
        state.retain_record(data::record(&marker,wire::RemoteWrite::NotAttempted),completion(wire::Settlement::Pending,wire::Finality::Pending),wire::Reason::None).unwrap();
        state.observe_remote(&marker,&write).unwrap();
        state.retain_record(data::record(&marker,wire::RemoteWrite::AttemptedOutcomeUnknown),completion(wire::Settlement::Unknown,wire::Finality::Unknown),wire::Reason::JournalIncomplete).unwrap();
        assert_eq!(state.view.records[0].write,write);assert_eq!(state.records[0].write,write);
        assert_eq!(state.view.records[0].completion.cleanup,wire::Settlement::Unknown);
        let conflict=if matches!(write,wire::RemoteWrite::AcknowledgedCreated {..}) {wire::RemoteWrite::AcknowledgedUpdated {status_code:204}}
            else {wire::RemoteWrite::AcknowledgedCreated {status_code:201}};
        assert!(state.observe_remote(&marker,&conflict).is_err());assert_eq!(state.view.records[0].write,write);
    }
}
#[test]
fn original_record_identity_is_immutable_and_unknown_history_is_not_native_work() {
    let mut state=State::new();let marker="a".repeat(32);
    state.retain_record(data::record(&marker,wire::RemoteWrite::AttemptedOutcomeUnknown),completion(wire::Settlement::Unknown,wire::Finality::Unknown),wire::Reason::CleanupUnknown).unwrap();
    assert!(!state.native_work_pending());assert!(state.material_settled() && state.memory_reserved());
    let mut changed=data::record(&marker,wire::RemoteWrite::AttemptedOutcomeUnknown);changed.prepared.environment_id="999".into();
    changed.intent_sha256=changed.prepared.intent_digest().unwrap();
    assert!(state.retain_record(changed,completion(wire::Settlement::Confirmed,wire::Finality::Settled),wire::Reason::None).is_err());
    assert_eq!(state.records[0].prepared.environment_id,"789");assert!(!state.native_work_pending());
    assert_eq!(state.view.records[0].completion.finality,wire::Finality::Unknown);
}
#[test]
fn history_refuses_overflow_without_truncating_required_original_rows() {
    let mut state=State::new();
    for n in 0..wire::RECORD_LIMIT {state.retain_record(data::record(&format!("{n:032x}"),wire::RemoteWrite::AttemptedOutcomeUnknown),
        completion(wire::Settlement::Unknown,wire::Finality::Unknown),wire::Reason::CleanupUnknown).unwrap();}
    let before=state.snapshot();assert!(before.fits_wire());
    assert!(state.retain_record(data::record(&format!("{:032x}",wire::RECORD_LIMIT),wire::RemoteWrite::AttemptedOutcomeUnknown),
        completion(wire::Settlement::Unknown,wire::Finality::Unknown),wire::Reason::CleanupUnknown).is_err());
    assert_eq!(state.snapshot(),before);assert_eq!(state.records.len(),wire::RECORD_LIMIT);
    assert!(state.records.capacity()<=wire::RECORD_LIMIT && state.view.records.capacity()<=wire::RECORD_LIMIT);
}

#[test]
fn idle_status_and_retained_empty_history_backing_remain_accounted() {
    let mut state=State::new();assert_eq!(state.memory_capacity(),0);
    state.view.session_id=Some("a".repeat(32));
    assert!(!state.memory_reserved());assert_eq!(state.memory_capacity(),32);
    state.records.try_reserve_exact(1).unwrap();
    assert!(state.records.is_empty() && state.memory_reserved());assert_eq!(state.memory_capacity(),wire::WORKING_RESERVATION);
    state.reset_session_view();assert_eq!(state.records.capacity(),0);assert_eq!(state.view.records.capacity(),0);
    assert!(!state.memory_reserved());assert_eq!(state.memory_capacity(),0);
    state.view.operation=Some(wire::Operation {id:"b".repeat(32),kind:wire::Kind::Prepare.into(),phase:wire::Phase::Settled,reason:wire::Reason::RunnerUnverified});
    assert!(state.memory_reserved());assert_eq!(state.memory_capacity(),wire::WORKING_RESERVATION);
    state.reset_session_view();assert!(!state.memory_reserved());
}
