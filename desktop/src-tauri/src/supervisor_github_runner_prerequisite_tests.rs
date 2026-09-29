//! Inert owner/bookkeeping DATA only. Never a successful native result, OS
//! handle, installed grant, child, worker, actual EOF or original join evidence.
use super::*;
#[test]
fn runner_claim_refuses_other_domains_original_loss_stop_failure_and_its_first_endpoint() {
    let now=Instant::now();let mut state=OwnerState::new(now+OPERATION_TIME,None);
    assert!(runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    for profile in [Profile::Passive(Method::Capabilities),Profile::GitHubReadOnly,Profile::GitHubDevice(device_protocol::Step::Start),
        Profile::GitHubDevice(device_protocol::Step::Poll),Profile::GitHubPreflight,Profile::GitHubRelease,Profile::GitHubInputGroup] {
        assert!(!runner_claim_clear(true,profile,&state,now,false,false,false));
    }
    assert!(!github_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    assert!(!device_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    assert!(!runner_claim_clear(false,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,state.endpoint,false,false,false));
    for (stopping,disabled,stop) in [(true,false,false),(false,true,false),(false,false,true)] {
        assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,stopping,disabled,stop));
    }
    state.fail_at(BridgeError::timeout(),now);let cleanup=state.cleanup_endpoint;
    state.fail_at(BridgeError::shutdown(),now+Duration::from_secs(1));assert_eq!(state.cleanup_endpoint,cleanup);
    assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    state.error=None;assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    state.cleanup_endpoint=None;state.unknown=true;assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
    state.unknown=false;state.terminal=true;assert!(!runner_claim_clear(true,Profile::GitHubRunnerPrerequisite,&state,now,false,false,false));
}
fn negative_ticket() -> GitHubRunnerTicket {
    let receipt=Arc::new(Mutex::new(GitHubRunnerReceipt::Pending));let mut owner=super::tests::inert_owner();
    owner.profile=Profile::GitHubRunnerPrerequisite;owner.runner_receipt=Some(receipt.clone());
    GitHubRunnerTicket {owner:Arc::new(owner),receipt,admitted_at:Instant::now()}
}
#[test]
fn control_mailbox_and_unknown_do_not_supply_a_consumable_result_or_another_owners_receipt() {
    let ticket=negative_ticket();let unrelated=negative_ticket();
    assert_eq!(ticket.state(),GitHubRunnerState::Pending);assert!(ticket.take_settled().is_none());
    let observed=GitHubRunnerObservedControl {observed_at:ticket.admitted_at(),control:github_protocol::GitHubReadControl {
        reason:github_protocol::Reason::RateLimited,credential_expires_at:None,cooldown_seconds:Some(7),cooldown_blocked:false}};
    *lock(&ticket.owner.runner_control)=Some(observed.clone());
    assert_eq!(ticket.observed_control().unwrap().observed_at,observed.observed_at);
    assert!(ticket.take_settled().is_none()); // Framed RESULT control is not EOF/finality.
    *lock(&ticket.receipt)=GitHubRunnerReceipt::RetainedUnknown;
    assert_eq!(ticket.state(),GitHubRunnerState::RetainedUnknown);assert!(ticket.take_settled().is_none());
    // Inject ONLY a negative bookkeeping disposition, never a successful native
    // result. This exercises consuming identity routing without forging proof.
    *lock(&ticket.receipt)=GitHubRunnerReceipt::Settled {outcome:Some(Err(BridgeError::cleanup_unknown())),
        settled_at:Instant::now(),was_unknown:true};
    let result=ticket.take_settled().unwrap();assert!(result.was_unknown && result.outcome.is_err());
    assert!(result.belongs_to(&ticket) && !result.belongs_to(&unrelated));assert!(ticket.take_settled().is_none());
    assert_eq!(ticket.state(),GitHubRunnerState::Settled {was_unknown:true});
    ticket.stop();assert!(lock(&unrelated.owner.state).error.is_none());
}
#[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu",not(all(feature="development-runtime",debug_assertions))))]
#[test]
fn runner_slots_cannot_borrow_another_profile_or_accept_mixed_original_books() {
    let mut resources=Resources::default();let profile=Profile::GitHubRunnerPrerequisite;
    assert!(installed_settlement_slots(&resources,profile).is_err());
    resources.github_runner=Some(Arc::new(Mutex::new(GitHubRunnerPrerequisiteRuntimeSlots::new())));
    assert!(matches!(installed_settlement_slots(&resources,profile),Ok(Some(InstalledSettlementSlots::GitHubRunnerPrerequisite(_)))));
    for other in [Profile::Passive(Method::Capabilities),Profile::GitHubReadOnly,Profile::GitHubDevice(device_protocol::Step::Poll),
        Profile::GitHubInputGroup,Profile::GitHubPreflight,Profile::GitHubRelease] {
        assert!(installed_settlement_slots(&resources,other).is_err());
    }
    resources.github_input_group=Some(Arc::new(Mutex::new(GitHubInputGroupRuntimeSlots::new())));
    assert!(installed_settlement_slots(&resources,profile).is_err());resources.github_input_group=None;
    resources.passive=Some(Arc::new(Mutex::new(PassiveRuntimeSlots::new())));
    assert!(installed_settlement_slots(&resources,profile).is_err());resources.passive=None;
    passive_worker_lost(&resources);
    let original=lock(resources.github_runner.as_ref().unwrap());assert!(!original.never_started() && !original.settled());
}
