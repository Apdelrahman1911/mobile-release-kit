//! Fixed Fetch selection on the SAME installed GitLocal slots/Book. The
//! public upstream Git source inspection is not an Apple CLT build nomination.
//! No PATH, xcode-select, executable picker, env flag or alternate TLS stack.
use super::*;

// Root must populate this only from independently reviewed *actual* protected
// CLT build/source applicability evidence, not a version string or fixture.
// All implemented owner paths remain unavailable until that evidence exists.
const NOMINATED_CLT_GIT_SHA256: Option<&str> = None;

pub(super) fn available() -> bool {
    macos_bindings() && NOMINATED_CLT_GIT_SHA256.is_some_and(crate::git_read_protocol::digest)
}
pub(crate) fn matches_tool(snapshot: &crate::git_local_protocol::Snapshot) -> bool {
    available() && NOMINATED_CLT_GIT_SHA256 == Some(snapshot.sha256.as_str())
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
        assert!(NOMINATED_CLT_GIT_SHA256.is_none());
        assert!(!available());
    }
}
