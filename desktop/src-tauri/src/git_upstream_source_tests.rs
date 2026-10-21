//! Mac module DATA only. No filesystem/ACL/native call or closure fabricated.
use super::*;
#[test]
fn attempted_or_ambiguous_directory_creation_is_not_retirement_or_retry() {
    for phase in [Creation::Entered,Creation::Created,Creation::Collision,Creation::Unknown] {
        let mut owner=GitLocalSources::new();let mut state=State::new(upstream::tests::action()).ok().unwrap();
        state.creation_entered=true;state.creations.push(Created{index:0,state:phase});owner.upstream=Some(state);
        assert!(!owner.upstream_retirable());owner.retain_upstream_unknown();assert!(owner.close_failed&&owner.first==Some(Reason::CleanupUnknown));
        assert!(!owner.upstream_retirable());assert!(owner.book.slots.is_empty());
    }
    assert!(creation_result(&Err(nix::errno::Errno::EEXIST))==Creation::Collision);
    assert!(creation_result(&Err(nix::errno::Errno::EIO))==Creation::Unknown);
    assert!(creation_result(&Ok(()))==Creation::Created);
}
#[test]
fn upstream_roster_charges_both_full_chains_and_working_originals_without_close_credit() {
    let first=State::new(upstream::tests::action()).ok().unwrap();let n=first.paths.len();assert_eq!(first.extra(),Some(n+5));
    let mut a=upstream::tests::action();a.branch="refs/heads/team/nested/main".into();let nested=State::new(a).ok().unwrap();
    assert_eq!(nested.extra(),first.extra().and_then(|v|v.checked_add(4)));
    assert!(State::working_bytes().unwrap()>=1024*1024+std::mem::size_of::<State>());
    assert_eq!(SOURCE_LIMIT,128);
    assert!(roster_limit([3,5],42+n+5).ok().unwrap() <= SOURCE_LIMIT);
    let parent=upstream::Parent{name:".".into(),identity:(1,2,0o40700,1001,1001,2,0,0,0),
        names:(0..upstream::MAX_NAMES).map(|i|format!("n{i:04}")).collect()};
    let mut next=upstream::Parent{name:"refs".into(),identity:parent.identity,names:vec![]};
    assert!(parent_room(std::slice::from_ref(&parent),&next));
    next.names.push("one-too-many".into());
    assert!(!parent_room(std::slice::from_ref(&parent),&next));
    next.names=vec!["x".repeat(upstream::MAX_NAME_BYTES+1)];
    assert!(!parent_room(&[],&next));
}
