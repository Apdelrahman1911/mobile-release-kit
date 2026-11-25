//! Commit-only native GUI approval. Uses the original successful Observe and
//! shared Doc/Edit/inbox admission; no public observation becomes authority.
use super::*;
use crate::service_git_commit_protocol::{self as commit, Draft, Family};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommitAllow {
    project_id: String,
    expected_document_revision: u32,
    expected_permission_revision: PermissionRevision,
    read_operation_id: String,
    message: String,
    author_name: String,
    author_email: String,
    consent_version: String,
}
pub(crate) fn decode_commit_allow(bytes: &[u8]) -> Result<CommitAllow, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > local::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    let args = CommitAllow::deserialize(&value).map_err(|_| BridgeError::invalid())?;
    if args.project_id.is_empty()
        || args.project_id.len() > 64
        || !wire::native_id(&args.read_operation_id)
        || !(1..u32::MAX).contains(&args.expected_document_revision)
        || args.consent_version != commit::CONSENT
    {
        return Err(BridgeError::invalid());
    }
    // Decode is bounded; the retained private draft is constructed once at
    // actual Allow, not supplied by a CLI command or copied to history.
    Ok(args)
}

impl DocumentBinding {
    pub(crate) fn agent_git_commit_access(
        &self,
        window: &str,
    ) -> Result<MainAccess<commit::Access>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let book = self.inner.agent_git_index.book.lock()
            .map_err(|_| public(Error::StateUnknown))?;
        let access = match self.git_index_service()? {
            Some(s) => s.git_index_requests().commit_access().map_err(public)?,
            None => commit::Access::empty(),
        };
        Ok(MainAccess::new(access, book.permission_revision()))
    }
    pub(crate) fn allow_agent_git_commit(
        &self,
        window: &str,
        args: CommitAllow,
    ) -> Result<MainAccess<commit::Access>, BridgeError> {
        let draft =
            Draft::new(args.message, args.author_name, args.author_email).map_err(public)?;
        let value = self.allow_agent_git_files(
            window,
            Allow {
                project_id: args.project_id,
                expected_document_revision: args.expected_document_revision,
                expected_permission_revision: args.expected_permission_revision,
                read_operation_id: args.read_operation_id,
                action: wire::Action::Commit,
                paths: Vec::new(),
                consent_version: args.consent_version,
            },
            Some(draft),
        )?;
        let value = value.map_access(commit::Access);
        value.access.validate().map_err(public)?;
        Ok(value)
    }
    pub(crate) fn revoke_agent_git_commit(
        &self,
        window: &str,
    ) -> Result<MainAccess<commit::Access>, BridgeError> {
        self.revoke_agent_git_files(window, Family::Commit)
            .map(|value| value.map_access(commit::Access))
    }
}

pub(super) fn whole_selection(value: &read::Projection) -> Result<wire::Selection, BridgeError> {
    if !successful_observe(value)
        || !value.result["observation"]["restrictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        return Err(public(Error::Conflict));
    }
    let rows = value.result["observation"]["changes"]
        .as_array()
        .ok_or_else(|| public(Error::Conflict))?;
    let mut paths = Vec::new();
    for row in rows {
        if row["conflict"].as_bool() != Some(false) {
            return Err(public(Error::Conflict));
        }
        let mark = row["index"]
            .as_str()
            .ok_or_else(|| public(Error::Conflict))?;
        if mark.len() != 1 {
            return Err(public(Error::Conflict));
        }
        // Same whole-index meaning as the existing native Commit planner:
        // untracked/ignored files are not staged merely because they appear
        // in the current observation. Never stage them as part of Commit.
        if !matches!(mark, " " | "." | "?" | "!") {
            if paths.len() >= wire::PATH_LIMIT {
                return Err(public(Error::Conflict));
            }
            paths.push(
                row["path"]
                    .as_str()
                    .ok_or_else(|| public(Error::Conflict))?
                    .into(),
            );
        }
    }
    paths.sort();
    wire::Selection::new_shared(
        wire::Action::Commit,
        value.result["observation"]["revision"]
            .as_str()
            .ok_or_else(|| public(Error::Conflict))?
            .into(),
        paths,
    )
    .map_err(public)
}

pub(super) fn action(scope: &requests::NativeScope) -> Result<local::Action, BridgeError> {
    let selection = scope.selection.files().map_err(public)?;
    match (&scope.commit, selection.summary.action) {
        (Some(draft), wire::Action::Commit) => local::Action::approved_commit(
            selection.summary.repository_revision.clone(),
            draft,
        ),
        (None, wire::Action::Stage | wire::Action::Unstage) => native_action(selection),
        _ => Err(BridgeError::invalid()),
    }
}

/// This additional match never creates a review. The caller already holds
/// the actual joined native Prepare/ReadyReview and its original scope/link.
pub(in crate::asset_session) fn review_matches(
    scope: &requests::NativeScope,
    review: &local::FileReview,
) -> bool {
    let Ok(action) = action(scope) else {
        return false;
    };
    let Ok(selection) = scope.selection.files() else { return false; };
    review.action == action.kind()
        && review.expected_revision == selection.summary.repository_revision
        && review.paths == selection.paths
        && review.whole_index == (selection.summary.action == wire::Action::Commit)
}

#[cfg(test)]
#[path = "service_git_commit_document_tests.rs"]
mod tests;
