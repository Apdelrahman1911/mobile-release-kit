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
fn nomination(kind: crate::git_local_protocol::Kind) -> [Option<&'static str>; 2] {
    match kind {
        crate::git_local_protocol::Kind::Push => NOMINATED_CLT_GIT_SHA256,
        crate::git_local_protocol::Kind::PushNewBranch => NOMINATED_NEW_BRANCH_CLT_GIT_SHA256,
        _ => [None, None],
    }
}
fn nominations_valid(slots: [Option<&str>; 2]) -> bool {
    slots.iter().any(Option::is_some)
        && slots.iter().flatten().all(|sha| crate::git_read_protocol::digest(sha))
        && !matches!(slots, [Some(first), Some(second)] if first == second)
}
fn nominated(slots: [Option<&str>; 2], sha256: &str) -> bool {
    nominations_valid(slots) && slots.contains(&Some(sha256))
}
pub(super) fn available_for(kind: crate::git_local_protocol::Kind) -> bool {
    macos_bindings() && nominations_valid(nomination(kind))
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
