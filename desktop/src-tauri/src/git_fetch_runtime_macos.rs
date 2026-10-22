//! Fixed Fetch selection on the SAME installed GitLocal slots/Book. The
//! public upstream Git source inspection is not an Apple CLT build nomination.
//! No PATH, xcode-select, executable picker, env flag or alternate TLS stack.
use super::*;

// Root may populate these two slots only from independently reviewed *actual* protected
// CLT build/source applicability evidence, not a version string or fixture.
// All implemented owner paths remain unavailable until that evidence exists.
// One occupied slot is valid; a duplicate or malformed occupied slot refuses
// the entire list. An identical Git build on two hosts needs only one slot.
const NOMINATED_CLT_GIT_SHA256: [Option<&str>; 2] = [None, None];

fn nominations_valid(slots: [Option<&str>; 2]) -> bool {
    slots.iter().any(Option::is_some)
        && slots.iter().flatten().all(|sha| crate::git_read_protocol::digest(sha))
        && !matches!(slots, [Some(first), Some(second)] if first == second)
}
fn nominated(slots: [Option<&str>; 2], sha256: &str) -> bool {
    nominations_valid(slots) && slots.contains(&Some(sha256))
}

pub(super) fn available() -> bool {
    macos_bindings() && nominations_valid(NOMINATED_CLT_GIT_SHA256)
}
pub(crate) fn matches_tool(snapshot: &crate::git_local_protocol::Snapshot) -> bool {
    available() && nominated(NOMINATED_CLT_GIT_SHA256, snapshot.sha256.as_str())
}
pub(super) fn selection() -> Result<VerifiedRuntime, BridgeError> {
    if !available() {
        return Err(BridgeError::unavailable("Fetch needs a reviewed protected Apple Command Line Tools Git provider. Local Git actions remain separate."));
    }
    let cwd = crate::installed_runtime::runtime_root();
    Ok(VerifiedRuntime {
        python: cwd.join("python/bin/python3"),
        bootstrap: cwd.join("git_remote_bootstrap.py"),
        core: cwd.join("core.zip"),
        cwd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upstream_source_or_installed_version_does_not_supply_missing_clt_nomination() {
        assert_eq!(NOMINATED_CLT_GIT_SHA256, [None, None]);
        assert!(!available());
    }

    #[test]
    fn two_closed_fetch_slots_match_only_distinct_complete_digests() {
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
        assert!(!nominations_valid([Some(&first), Some(&first)]));
        for invalid in ["".to_owned(), "a".repeat(63), "a".repeat(65),
            "A".repeat(64), "g".repeat(64), format!("{first}\n")] {
            assert!(!nominations_valid([Some(&first), Some(&invalid)]));
            assert!(!nominated([Some(&first), Some(&invalid)], &first));
        }
    }
}
