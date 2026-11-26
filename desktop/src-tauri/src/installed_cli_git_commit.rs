//! Five closed whole-index commands. All framing, request identity, transport,
//! unknown-response handling and output limits stay on the existing client.
use super::*;
use crate::service_git_commit_protocol::Family;

pub(super) const COMMANDS: [CommandCapability; 5] = [
    CommandCapability { command: "git-commit-scope", arguments: &["PROJECT_ID"], description: "Read the Desktop-approved whole staged index; the private commit draft stays in Desktop." },
    CommandCapability { command: "git-commit-prepare", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "GRANT_ID"], description: "Prepare one explicitly approved local commit using the original Git owner; no Apply." },
    CommandCapability { command: "git-commit-start", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID", "PREPARE_OPERATION_ID", "REVIEW_ID"], description: "Commit that exact whole-index native review once; no hooks, signing, branch switch or push." },
    CommandCapability { command: "git-commit-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Inspect the same original commit request without replay." },
    CommandCapability { command: "git-commit-cancel", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Request original STOP; no mutation or cleanup outcome is inferred." },
];
pub(super) fn recognizes(args: &[OsString]) -> bool {
    git_index::recognizes_for(args, Family::Commit)
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    git_index::run_for(args, Family::Commit)
}
