//! Mac-gated finite custody DATA only. No native FD, unlink/close or receipt.
use super::*;
#[test]
fn ambiguous_rename_lock_preserves_original_slots_without_fake_close_or_retry() {
    for phase in [
        OriginalState::Reserved,
        OriginalState::Acquiring,
        OriginalState::Unknown,
    ] {
        let mut owner = GitLocalSources::new();
        owner.book.begin(4, 0, 0).unwrap();
        let parent = owner.book.reserve(None, b"parent").unwrap();
        let index = owner.book.reserve(Some(parent), b"main.lock").unwrap();
        let other = owner.book.reserve(Some(parent), b"next.lock").unwrap();
        let tail = owner.book.reserve(Some(parent), b"tail").unwrap();
        owner.book.slots[index].state = phase;
        let mut state = State::new().unwrap();
        state.source = Some(Edge {
            parent,
            name: b"main".to_vec(),
            original: None,
            maximum: 65,
        });
        state.locks.push(RefLock {
            index,
            unlink_claimed: false,
            unlinked: false,
        });
        state.locks.push(RefLock {
            index: other,
            unlink_claimed: false,
            unlinked: false,
        });
        owner.rename = Some(state);
        assert!(owner.check_rename_locks(&mut || false).is_err());
        assert!(!owner.close_rename_book(&mut |_| false));
        assert!(!owner.close_rename_book(&mut |_| false));
        // Even a present expected identity cannot replace the unavailable
        // original parent descriptor. This remains DATA, not native custody.
        owner.rename.as_mut().unwrap().parent_current =
            Some((1, 2, 0o040700, 501, 20, 2, 0, 0, 0));
        assert!(owner.check_rename_locks(&mut || false).is_err());
        assert!(!owner.close_rename_book(&mut |_| false));
        assert!(
            owner.book.slots[index].state == phase
                && owner.book.slots[tail].state == OriginalState::Reserved
        );
        assert!(!owner
            .rename
            .as_ref()
            .unwrap()
            .locks
            .iter()
            .any(|r| r.unlink_claimed || r.unlinked));
        assert!(!owner.book.terminal);
        // No FD supplied by this DATA fixture. Dispose inert allocations only.
        for slot in &mut owner.book.slots {
            assert!(slot.fd.is_none());
            slot.state = OriginalState::NoHandle;
        }
        assert!(owner.book.close_all());
    }
}
#[test]
fn rename_roster_counts_full_ref_and_log_chains_without_future_close_credit() {
    let mut r = crate::git_rename_protocol::tests::review();
    let initial = State::extra(Some(&wire::Review::Rename(r.clone()))).unwrap();
    r.branch = "refs/heads/group/main".into();
    r.target_ref = "refs/heads/group/next".into();
    r.name = "group/next".into();
    assert_eq!(
        State::extra(Some(&wire::Review::Rename(r))),
        Some(initial + 2)
    );
    assert_eq!(State::extra(None), Some(0));
    assert!(State::working_bytes().unwrap() > 7 * PATH_LIMIT);
}
#[test]
fn failed_original_rename_rematch_is_sticky_and_cannot_release_ref_locks() {
    let mut owner = GitLocalSources::new();
    owner.first = Some(Reason::SourceChanged);
    owner.retain_rename_unknown();
    assert!(owner.first == Some(Reason::CleanupUnknown) && owner.close_failed);
    assert!(owner.close(&mut |_| false).is_err());
    assert!(!owner.settled());
}
