//! Push is a closed selection of the SAME installed GitLocal slots. A Fetch
//! nomination alone does not prove receive-pack/pre-push/dry-run applicability.
//! No PATH, environment override, version-string or provider fallback.
use super::*;

// Only Root's independently reviewed actual protected-CLT behavioral evidence
// may nominate this fixed build. Source/inert tests are deliberately not it.
const NOMINATED_CLT_GIT_SHA256: Option<&str> = None;
// Existing-target Push/observer evidence cannot nominate empty-advertisement
// parsing, full reachable-history review or expected-zero creation.
const NOMINATED_NEW_BRANCH_CLT_GIT_SHA256: Option<&str> = None;
fn nomination(kind: crate::git_local_protocol::Kind) -> Option<&'static str> {
    match kind {
        crate::git_local_protocol::Kind::Push => NOMINATED_CLT_GIT_SHA256,
        crate::git_local_protocol::Kind::PushNewBranch => NOMINATED_NEW_BRANCH_CLT_GIT_SHA256,
        _ => None,
    }
}
pub(super) fn available_for(kind: crate::git_local_protocol::Kind) -> bool {
    macos_bindings() && nomination(kind).is_some_and(crate::git_read_protocol::digest)
}
pub(crate) fn matches_tool_for(kind: crate::git_local_protocol::Kind, snapshot: &crate::git_local_protocol::Snapshot) -> bool {
    available_for(kind) && nomination(kind) == Some(snapshot.sha256.as_str())
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
        assert!(NOMINATED_CLT_GIT_SHA256.is_none());
        assert!(!available());
        assert!(NOMINATED_NEW_BRANCH_CLT_GIT_SHA256.is_none());
        assert!(!available_for(crate::git_local_protocol::Kind::PushNewBranch));
    }
}
