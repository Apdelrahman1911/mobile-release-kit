//! ID-only Remote facade on the existing CLI collector/IPC/request owner.
//! No automatic Prepare/Start, shell command, credential or remote read here.
use super::*;
use crate::{
    service_git_commit_protocol::Family, service_git_protocol as git,
    service_git_remote_protocol as remote,
};
pub(super) const NAMES: [&str; 5] = [
    "git-remote-scope",
    "git-remote-prepare",
    "git-remote-start",
    "git-remote-status",
    "git-remote-cancel",
];
pub(super) const COMMANDS: [CommandCapability; 5] = [
    CommandCapability {
        command: "git-remote-scope",
        arguments: &["PROJECT_ID"],
        description: "Read the exact Desktop-approved Fetch or Push.",
    },
    CommandCapability {
        command: "git-remote-prepare",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "GRANT_ID"],
        description: "Request its original native Remote review.",
    },
    CommandCapability {
        command: "git-remote-start",
        arguments: &[
            "PROJECT_ID",
            "SERVICE_INSTANCE",
            "REQUEST_ID",
            "PREPARE_OPERATION_ID",
            "REVIEW_ID",
        ],
        description: "Apply that Remote review once.",
    },
    CommandCapability {
        command: "git-remote-status",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Observe the original without replay.",
    },
    CommandCapability {
        command: "git-remote-cancel",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Request original STOP, not settlement.",
    },
];
pub(super) fn recognizes(args: &[OsString]) -> bool {
    git_index::recognizes_for(args, Family::Remote)
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    git_index::run_for(args, Family::Remote)
}
pub(super) fn output(
    response: &p::Response,
    project: &Id,
    origin: Option<&git::Query>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    let encoded = p::encode_response(response)?;
    let (code, human) = match (&response.response, origin) {
        (p::ResponseBody::GitRemoteScope(scope), None)
            if &scope.project_id == project
                && scope.service_instance == response.service_instance =>
        {
            let a = &scope.access;
            let mut text=String::from("One Desktop-selected Remote action. No arbitrary URL, token, force push, automatic fetch or remote retry.\n");
            if let Some(s) = &a.selection {
                text.push_str(&format!(
                    "{}: {} as {} (account {}, repository {}), {} {}. Selection {}.\n",
                    s.action.kind().label(),
                    s.account.repository,
                    s.account.login,
                    s.account.account_id,
                    s.account.repository_id,
                    s.action.remote(),
                    s.action.reference(),
                    s.selection_sha256
                ));
                if let remote::Action::Push {
                    local_ref,
                    old_oid,
                    new_oid,
                    ..
                } = &s.action
                {
                    text.push_str(&format!("Committed {local_ref}: cached {old_oid} -> {new_oid}; original native review must still check the complete outgoing history.\n"));
                }
                if a.enabled {
                    text.push_str(&format!(
                        "Prepare: mrk git-remote-prepare {} {} {} --json\n",
                        project.as_str(),
                        scope.service_instance.as_str(),
                        a.grant_id.as_ref().ok_or(Error::StateUnknown)?.as_str()
                    ));
                } else {
                    text.push_str(if a.consumed {"Permission consumed. Use mrk requests to find the original request; do not submit another.\n"} else {"Permission is not confirmed active.\n"});
                }
            } else {
                text.push_str("Select the real repository/account and explicitly Allow one Remote action in Desktop.\n");
            }
            (0, text)
        }
        (p::ResponseBody::GitRemoteRequest(value), Some(q))
            if &value.progress.origin == q
                && &q.project_id == project
                && q.service_instance == response.service_instance =>
        {
            let s = &value.progress;
            let code = if s.settlement == p::Settlement::Unknown
                || s.outcome == Some(p::OperationState::RecoveryRequired)
            {
                6
            } else if matches!(
                s.state,
                git::State::Refused | git::State::Cancelled | git::State::Expired
            ) || matches!(
                s.outcome,
                Some(p::OperationState::Failed | p::OperationState::Cancelled)
            ) {
                3
            } else {
                0
            };
            let mut text = format!(
                "{} — {:?}; settlement {:?}.\n{}",
                s.selection.action.kind().label(),
                s.state,
                s.settlement,
                git_index::receipt(q, Family::Remote)
            );
            if let Some(r) = &s.review {
                text.push_str(&format!(
                    "Original review {}: source {}, refs {}, digest {}.\n",
                    r.review_id, r.source_revision, r.reference_revision, r.review_digest
                ));
                match &r.preview {
                    remote::Preview::Fetch {target_ref,expected_target,candidate_ref_oid}=>text.push_str(&format!("Fetch only {target_ref}: {} -> {candidate_ref_oid}; no checkout, merge or local branch movement.\n",expected_target.as_deref().unwrap_or("absent"))),
                    remote::Preview::Push {branch,upstream_ref,expected_remote_oid,head,commit_count,commits_sha256}=>text.push_str(&format!("Normal Push {branch} to {upstream_ref}: {expected_remote_oid} -> {head}; {commit_count} outgoing commits, digest {commits_sha256}. Messages/objects are withheld; this is not a secret-safety guarantee.\n")),
                }
                if s.state == git::State::Prepared && r.can_apply() {
                    text.push_str(&format!(
                        "Start once: mrk git-remote-start {} {} {} {} {} --json\n",
                        q.project_id.as_str(),
                        q.service_instance.as_str(),
                        q.request_id.as_str(),
                        s.prepare_operation_id.as_ref().ok_or(Error::StateUnknown)?,
                        r.review_id
                    ));
                } else if !r.can_apply() {
                    text.push_str("That fetched tip is already cached. Close or cancel this review; no Apply is offered.\n");
                }
            }
            if let Some(r) = &value.result {
                text.push_str(&format!(
                    "Original returned effect: {:?}, {:?}.\n",
                    r.state, r.effect_phase
                ));
                for name in &r.retained_paths {
                    text.push_str(&format!("Retained diagnostic name: {name}\n"));
                }
            }
            text.push_str("Never repeat an unconfirmed send or erase its pending journal. A fresh read is a separate explicit Desktop Activity action; it cannot settle or replay this request.\n");
            text.push_str(if s.history_available {
                "Shared history copied this original status; it is not a cleanup receipt.\n"
            } else {
                "Shared history is not confirmed; retain these original IDs.\n"
            });
            (code, text)
        }
        (p::ResponseBody::Error(e), _) => return Err(*e),
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
