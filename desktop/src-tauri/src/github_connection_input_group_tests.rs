// Pure completion/control aggregation. No active ticket or native receipt.
use super::*;
#[test]
fn any_reply_is_not_a_substitute_for_explicit_network_cleanup() {
    for unknown in [false,true] {for read in [false,true] {
        for network in [None,Some(p::Settlement::NotRun),Some(p::Settlement::Confirmed),Some(p::Settlement::Unknown),Some(p::Settlement::Pending)] {
            let expected=if !unknown && (matches!(network,Some(p::Settlement::NotRun|p::Settlement::Confirmed)) || network.is_none() && !read) {
                p::Settlement::Confirmed
            } else {p::Settlement::Unknown};
            assert_eq!(completion_cleanup(network,read,unknown),expected);
        }
    }}
}
#[test]
fn repeated_control_uses_original_observation_time_and_cannot_restart_cooldown() {
    let mut state=ConnectionState::new();let at=Instant::now();let control=GitHubReadControl {
        reason:Reason::RateLimited,credential_expires_at:None,cooldown_seconds:Some(30),cooldown_blocked:false};
    assert!(state.apply_control(&control,at));let end=state.cooldown;
    assert!(state.apply_control(&control,at));assert_eq!(state.cooldown,end);
    let weaker=GitHubReadControl {reason:Reason::None,credential_expires_at:None,cooldown_seconds:None,cooldown_blocked:false};
    assert!(state.apply_control(&weaker,at+Duration::from_secs(10)));assert_eq!(state.cooldown,end);
    assert!(state.cooldown.is_some_and(|end|end==at+Duration::from_secs(30)));
}

#[test]
fn runner_summary_is_redacted_history_not_a_private_admission_grant() {
    let mut state=ConnectionState::new();
    state.input.view.runner=Some(rp::Summary {result:rp::PublicResult::Safe,checked_at:Some("2026-09-28T12:00:00Z".into()),
        expires_at:Some("2026-09-28T12:02:00Z".into()),group_count:Some(0),runner_count:Some(0),scope:Some(rp::Coverage::Repository),reason:p::Reason::None});
    let status=state.input_status(false,Instant::now(),Reason::None);
    assert!(!status.available);assert!(state.input.runner.observation.is_none() && state.input.consent.is_none());
    state.revoke_input_runner(p::Reason::TargetChanged);
    let historical=state.input.view.runner.as_ref().unwrap();
    assert_eq!(historical.result,rp::PublicResult::Expired);assert_eq!(historical.group_count,Some(0));
    assert_eq!(historical.reason,p::Reason::TargetChanged);
    assert!(!state.input_work_pending()); // A historical summary is not an original worker.
    assert!(state.input_cancel("not-an-original-ticket").is_err());
}
