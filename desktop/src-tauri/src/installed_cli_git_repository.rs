//! Fixed local-repository facade. Parsing, original request IDs, uncertain
//! acknowledgements and IPC use the existing Git client without a new runner.
use super::*;
use crate::{
    service_git_commit_protocol::Family, service_git_protocol as git,
    service_git_repository_protocol as repository,
};

pub(super) const COMMANDS: [CommandCapability; 5] = [
    CommandCapability {
        command: "git-repository-scope",
        arguments: &["PROJECT_ID"],
        description: "Read one Desktop-selected local action.",
    },
    CommandCapability {
        command: "git-repository-prepare",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "GRANT_ID"],
        description: "Prepare its original native review.",
    },
    CommandCapability {
        command: "git-repository-start",
        arguments: &[
            "PROJECT_ID",
            "SERVICE_INSTANCE",
            "REQUEST_ID",
            "PREPARE_OPERATION_ID",
            "REVIEW_ID",
        ],
        description: "Apply that exact review once.",
    },
    CommandCapability {
        command: "git-repository-status",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Observe the original; never replay.",
    },
    CommandCapability {
        command: "git-repository-cancel",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Request original STOP, not settlement.",
    },
];
pub(super) fn recognizes(args: &[OsString]) -> bool {
    git_index::recognizes_for(args, Family::Repository)
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    git_index::run_for(args, Family::Repository)
}

pub(super) fn output(
    response: &p::Response,
    project: &Id,
    origin: Option<&git::Query>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    // Full validation precedes human output as well as --json. There is no
    // fallback to another family or a free-form response/result decoder.
    let encoded = p::encode_response(response)?;
    let (code, human) = match (&response.response, origin) {
        (p::ResponseBody::GitRepositoryScope(scope), None)
            if &scope.project_id == project
                && scope.service_instance == response.service_instance =>
        {
            let access = &scope.access;
            let mut text=String::from("One Desktop-approved local Git action. No initial commit, Fetch, Push or arbitrary Git command.\n");
            if let Some(selection) = &access.selection {
                text.push_str(&format!(
                    "{} — {}; selection {}.\n",
                    selection.action.label(),
                    if access.enabled {
                        "allowed once"
                    } else if access.consumed {
                        "consumed; keep original request"
                    } else {
                        "not allowed"
                    },
                    selection.selection_sha256
                ));
                text.push_str(&selection_text(&selection.action));
                if access.enabled {
                    text.push_str(&format!(
                        "Prepare: mrk git-repository-prepare {} {} {} --json\n",
                        project.as_str(),
                        scope.service_instance.as_str(),
                        access
                            .grant_id
                            .as_ref()
                            .ok_or(Error::StateUnknown)?
                            .as_str()
                    ));
                }
            } else {
                text.push_str(
                    "Select and explicitly Allow one local repository action in Desktop.\n",
                );
            }
            (0, text)
        }
        (p::ResponseBody::GitRepositoryRequest(status), Some(q))
            if &status.origin == q
                && &q.project_id == project
                && q.service_instance == response.service_instance =>
        {
            let code = if status.settlement == p::Settlement::Unknown
                || status.outcome == Some(p::OperationState::RecoveryRequired)
            {
                6
            } else if matches!(
                status.state,
                git::State::Refused | git::State::Cancelled | git::State::Expired
            ) || matches!(
                status.outcome,
                Some(p::OperationState::Failed | p::OperationState::Cancelled)
            ) {
                3
            } else {
                0
            };
            let mut text = format!(
                "{} — {:?}; settlement {:?}.\n{}",
                status.selection.action.label(),
                status.state,
                status.settlement,
                git_index::receipt(q, Family::Repository)
            );
            if let (Some(op), Some(review)) = (&status.prepare_operation_id, &status.review) {
                text.push_str(&format!(
                    "Review {}: source {}, digest {}.\n",
                    review.review_id, review.source_revision, review.review_digest
                ));
                text.push_str(&preview_text(&review.preview));
                text.push_str(&format!(
                    "Start once: mrk git-repository-start {} {} {} {} {} --json\n",
                    q.project_id.as_str(),
                    q.service_instance.as_str(),
                    q.request_id.as_str(),
                    op,
                    review.review_id
                ));
            }
            text.push_str(if status.history_available {
                "History copied this native status; it is not a cleanup receipt.\n"
            } else {
                "Shared history not confirmed. Retain the original request IDs.\n"
            });
            (code, text)
        }
        (p::ResponseBody::Error(error), _) => return Err(*error),
        _ => return Err(Error::StateUnknown),
    };
    let mut bytes = if json { encoded } else { human.into_bytes() };
    if json {
        bytes.push(b'\n');
    }
    if bytes.len() > git::STATUS_BYTES + 1 {
        return Err(Error::StateUnknown);
    }
    Ok((code, bytes))
}
fn selection_text(action: &repository::Action) -> String {
    match action {
        repository::Action::Initialize {}=>"Initialize an empty local repository on main; keep project files, no commit. Absence is checked only by native Prepare.\n".into(),
        repository::Action::BranchCreate {name,..}=>format!("Create local branch {name}; do not switch.\n"),
        repository::Action::BranchSwitch {name,..}=>format!("Switch to local branch {name}; native review checks supported tracked-file effects.\n"),
        repository::Action::BranchRename {name,..}=>format!("Rename the current local branch to {name}; no remote branch rename.\n"),
        repository::Action::FastForward {target_ref,target_oid,..}=>format!("Fast-forward to cached {target_ref} at {target_oid}; never fetch.\n"),
    }
}
fn preview_text(preview: &repository::Preview) -> String {
    match preview {
        repository::Preview::Initialize {initial_branch,object_format}=>format!("Empty {object_format} repository on {initial_branch}; no synthetic index or existing-branch observation.\n"),
        repository::Preview::BranchCreate {head,target_ref,..}=>format!("Create {target_ref} at {head}; keep current checkout.\n"),
        repository::Preview::BranchSwitch {branch,target_ref,target_oid,changed_path_count,..}=>format!("{branch} -> {target_ref} at {target_oid}; {changed_path_count} tracked content changes.\n"),
        repository::Preview::BranchRename {branch,target_ref,config_moved,logging,..}=>format!("{branch} -> {target_ref}; branch config moved: {config_moved}; reflog enabled: {logging}.\n"),
        repository::Preview::FastForward {branch,target_ref,target_oid,changed_path_count,..}=>format!("Advance {branch} to cached {target_ref} at {target_oid}; {changed_path_count} tracked content changes, no fetch.\n"),
    }
}
