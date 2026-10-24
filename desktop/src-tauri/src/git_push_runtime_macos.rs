//! Push is a closed selection of the SAME installed GitLocal slots. A Fetch
//! nomination alone does not prove receive-pack/pre-push/dry-run applicability.
//! No PATH, environment override, version-string or provider fallback.
use super::*;

// Only Root's independently reviewed actual protected-CLT behavioral evidence
// may nominate either of these two fixed builds. Source/inert tests are not it.
// Empty slots are allowed; malformed/duplicate occupied slots refuse the list.
const NOMINATED_CLT_GIT_SHA256: [Option<&str>; 2] = [None, None];
// Existing-target Push/observer evidence cannot nominate empty-advertisement
// parsing, full reachable-history review or expected-zero creation.
const NOMINATED_NEW_BRANCH_CLT_GIT_SHA256: [Option<&str>; 2] = [None, None];
fn nomination_from<'a>(kind: crate::git_local_protocol::Kind,
    existing: [Option<&'a str>; 2], new_branch: [Option<&'a str>; 2]) -> [Option<&'a str>; 2] {
    match kind {
        crate::git_local_protocol::Kind::Push => existing,
        crate::git_local_protocol::Kind::PushNewBranch => new_branch,
        _ => [None, None],
    }
}
fn nomination(kind: crate::git_local_protocol::Kind) -> [Option<&'static str>; 2] {
    nomination_from(kind, NOMINATED_CLT_GIT_SHA256, NOMINATED_NEW_BRANCH_CLT_GIT_SHA256)
}
fn nominations_valid(slots: [Option<&str>; 2]) -> bool {
    slots.iter().any(Option::is_some)
        && slots.iter().flatten().all(|sha| crate::git_read_protocol::digest(sha))
        && !matches!(slots, [Some(first), Some(second)] if first == second)
}
fn nominated(slots: [Option<&str>; 2], sha256: &str) -> bool {
    nominations_valid(slots) && slots.contains(&Some(sha256))
}
fn available_with(installed: bool, aarch64: bool, slots: [Option<&str>; 2]) -> bool {
    installed && aarch64 && nominations_valid(slots)
}
pub(super) fn available_for(kind: crate::git_local_protocol::Kind) -> bool {
    // Both Push kinds need ARM evidence; universal bytes do not qualify Intel.
    available_with(macos_bindings(), cfg!(target_arch = "aarch64"), nomination(kind))
}
pub(crate) fn matches_tool_for(kind: crate::git_local_protocol::Kind, snapshot: &crate::git_local_protocol::Snapshot) -> bool {
    available_for(kind) && nominated(nomination(kind), snapshot.sha256.as_str())
}
pub(super) fn available() -> bool {
    available_for(crate::git_local_protocol::Kind::Push)
}
pub(crate) fn matches_tool(snapshot: &crate::git_local_protocol::Snapshot) -> bool {
    matches_tool_for(crate::git_local_protocol::Kind::Push, snapshot)
}
pub(super) fn selection() -> Result<VerifiedRuntime, BridgeError> {
    selection_for(crate::git_local_protocol::Kind::Push)
}
pub(super) fn selection_for(kind: crate::git_local_protocol::Kind) -> Result<VerifiedRuntime, BridgeError> {
    if !available_for(kind) {
        return Err(BridgeError::unavailable("Push needs a reviewed protected Apple Command Line Tools Git provider. No remote update was started."));
    }
    let cwd = crate::installed_runtime::runtime_root();
    Ok(VerifiedRuntime {
        python: cwd.join("python/bin/python3"),
        bootstrap: cwd.join("git_push_bootstrap.py"),
        core: cwd.join("core.zip"),
        cwd,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fetch_or_public_source_evidence_never_nominates_a_push_provider() {
        assert_eq!(NOMINATED_CLT_GIT_SHA256, [None, None]);
        assert!(!available());
        assert_eq!(NOMINATED_NEW_BRANCH_CLT_GIT_SHA256, [None, None]);
        assert!(!available_for(crate::git_local_protocol::Kind::PushNewBranch));
        assert_eq!(nomination(crate::git_local_protocol::Kind::Fetch), [None, None]);
    }

    #[test]
    fn both_push_kinds_require_installed_arm_and_their_own_valid_nomination() {
        use crate::git_local_protocol::Kind;
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let existing = [Some(first.as_str()), None];
        let new_branch = [None, Some(second.as_str())];
        for kind in [Kind::Push, Kind::PushNewBranch] {
            let selected = nomination_from(kind, existing, new_branch);
            for installed in [false, true] {
                for aarch64 in [false, true] {
                    assert_eq!(available_with(installed, aarch64, selected), installed && aarch64);
                }
            }
            for invalid in [[None, None], [Some(first.as_str()), Some(first.as_str())],
                [Some(first.as_str()), Some("invalid")]] {
                let selected = match kind {
                    Kind::Push => nomination_from(kind, invalid, new_branch),
                    _ => nomination_from(kind, existing, invalid),
                };
                assert!(!available_with(true, true, selected));
            }
        }
    }

    #[test]
    fn push_kinds_never_borrow_each_others_or_a_non_push_nomination() {
        use crate::git_local_protocol::Kind;
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let existing = [Some(first.as_str()), None];
        let new_branch = [None, Some(second.as_str())];
        assert_eq!(nomination_from(Kind::Push, existing, new_branch), existing);
        assert_eq!(nomination_from(Kind::PushNewBranch, existing, new_branch), new_branch);
        assert!(!nominated(nomination_from(Kind::Push, existing, new_branch), &second));
        assert!(!nominated(nomination_from(Kind::PushNewBranch, existing, new_branch), &first));
        for kind in [Kind::Stage, Kind::Unstage, Kind::Commit, Kind::BranchCreate,
            Kind::BranchSwitch, Kind::BranchRename, Kind::FastForward, Kind::Fetch,
            Kind::Initialize, Kind::SetUpstream] {
            let selected = nomination_from(kind, existing, new_branch);
            assert_eq!(selected, [None, None]);
            assert!(!available_with(true, true, selected));
        }
    }

    #[test]
    fn two_closed_push_slots_do_not_inherit_another_build_or_partial_list() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let foreign = "c".repeat(64);
        assert!(!nominations_valid([None, None]));
        for slots in [[Some(first.as_str()), None], [None, Some(first.as_str())],
            [Some(first.as_str()), Some(second.as_str())]] {
            assert!(nominations_valid(slots));
            assert!(nominated(slots, &first));
            assert!(!nominated(slots, &foreign));
        }
        assert!(nominated([Some(&first), Some(&second)], &second));
        assert!(!nominated([Some(&second), None], &first));
        assert!(!nominations_valid([Some(&first), Some(&first)]));
        for invalid in ["".to_owned(), "a".repeat(63), "a".repeat(65),
            "A".repeat(64), "g".repeat(64), format!("{first}\n")] {
            assert!(!nominations_valid([Some(&first), Some(&invalid)]));
            assert!(!nominated([Some(&first), Some(&invalid)], &first));
        }
    }
}
