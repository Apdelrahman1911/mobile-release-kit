//! Mac-gated comparison/finite-state DATA only. No native FD, filesystem,
//! account, ACL, unlink/close success or installed runtime is qualified here.
use super::*;

#[test]
fn switch_positive_metadata_prefix_is_exact_and_does_not_accept_generic_index_or_ref_receipts() {
    use wire::Publication::*;
    assert_eq!(publication_names(SwitchCheckoutReturned,true),Some(&[][..]));
    assert_eq!(publication_names(SwitchLogReturned,true),Some(&["logs/HEAD"][..]));
    assert_eq!(publication_names(SwitchHeadReturned,false),Some(&["HEAD"][..]));
    assert_eq!(publication_names(SwitchIndexReturned,true),Some(&["logs/HEAD","HEAD","index"][..]));
    assert_eq!(publication_names(SwitchIndexReturned,false),Some(&["HEAD","index"][..]));
    for v in [NotReported,IndexReturned,RefReturned,BranchRefReturned,SwitchLogReturned] {
        assert!(publication_names(v,false).is_none());
    }
}

#[test]
fn ambiguous_target_lock_acquisition_retains_all_original_routes_without_fake_cleanup_or_retry() {
    for phase in [OriginalState::Reserved,OriginalState::Acquiring,OriginalState::Unknown] {
        let mut owner=GitLocalSources::new();owner.book.begin(3,0,0).unwrap();
        let parent=owner.book.reserve(None,b"parent").unwrap();let index=owner.book.reserve(Some(parent),b"next.lock").unwrap();
        let other=owner.book.reserve(Some(parent),b"other").unwrap();owner.book.slots[index].state=phase;
        let mut state=State::new().unwrap();state.lock=Some(index);
        state.target=Some(Edge {parent,name:b"next".to_vec(),original:None,maximum:65});owner.switch=Some(state);
        assert!(!owner.close_switch_book(&mut |_|false));
        assert!(owner.book.slots[index].state==phase && owner.book.slots[other].state==OriginalState::Reserved);
        assert!(!owner.switch.as_ref().unwrap().unlink_claimed && !owner.book.terminal);
        assert!(!owner.close_switch_book(&mut |_|false));
        // No descriptor was ever supplied; retire these test DATA allocations.
        for slot in &mut owner.book.slots {assert!(slot.fd.is_none());slot.state=OriginalState::NoHandle;}
        assert!(owner.book.close_all());
    }
}

#[test]
fn one_attempt_slot_retirement_keeps_unknown_and_never_invents_missing_owned_descriptor_success() {
    let mut book=SourceBook::new();book.begin(1,0,0).unwrap();let index=book.reserve(None,b"data-only").unwrap();
    book.slots[index].state=OriginalState::Owned;let mut failures=0;
    assert!(!SourceBook::close_slot(&mut book.slots[index],&mut |_|failures+=1));
    assert!(book.slots[index].state==OriginalState::Unknown && book.slots[index].fd.is_none());
    assert!(!SourceBook::close_slot(&mut book.slots[index],&mut |_|failures+=1));assert_eq!(failures,2);
    assert!(!book.settled());book.slots[index].state=OriginalState::NoHandle;assert!(book.close_all());
}

#[test]
fn switch_extra_roster_is_charged_without_discount_for_aliases_review_or_future_close() {
    let mut r=crate::git_switch_protocol::tests::review();
    let one=State::extra(Some(&wire::Review::Switch(r.clone()))).unwrap();
    r.files[0].path="a/b/c.txt".into();r.paths[0]="a/b/c.txt".into();
    assert_eq!(State::extra(Some(&wire::Review::Switch(r))).unwrap(),one+2);
    assert_eq!(State::extra(None),Some(0));assert!(State::working_bytes().unwrap()>32*1024);
}

#[test]
fn uncertain_return_promotes_prior_known_refusal_so_original_lock_cleanup_cannot_run() {
    let mut owner=GitLocalSources::new();owner.first=Some(Reason::SourceChanged);
    owner.retain_switch_unknown();assert!(owner.first==Some(Reason::CleanupUnknown) && owner.close_failed);
    // No account/ACL/FD was entered; close must still preserve Unknown rather
    // than calling an empty Book a settled original after a lost return.
    assert!(owner.close(&mut |_|false).is_err());assert!(!owner.settled());
}
