//! Closed Stage/Unstage client. Paths come only from the actual Desktop grant;
//! no executable, raw Git command, diff, commit draft or native owner is made.
use super::*;
use crate::service_git_protocol as git;
use crate::service_git_commit_protocol::Family;

enum Command {
    Scope(Id),
    Prepare {
        project: Id,
        instance: Id,
        grant: Id,
    },
    Start(git::Start),
    Status(git::Query),
    Cancel(git::Query),
}
struct Parsed {
    family: Family,
    command: Command,
    json: bool,
}
fn names(family: Family) -> &'static [&'static str; 5] {
    match family {
        Family::Index => &["git-index-scope", "git-index-prepare", "git-index-start", "git-index-status", "git-index-cancel"],
        Family::Commit => &["git-commit-scope", "git-commit-prepare", "git-commit-start", "git-commit-status", "git-commit-cancel"],
        Family::Repository => &["git-repository-scope", "git-repository-prepare", "git-repository-start", "git-repository-status", "git-repository-cancel"],
    }
}
pub(super) fn recognizes(args: &[OsString]) -> bool { recognizes_for(args, Family::Index) }
pub(super) fn recognizes_for(args: &[OsString], family: Family) -> bool {
    args.first().and_then(|s| s.to_str()).is_some_and(|s| names(family).contains(&s))
}
fn query(project: &str, instance: &str, request: &str) -> Result<git::Query, Error> {
    Ok(git::Query {
        project_id: Id::parse(project)?,
        service_instance: Id::parse(instance)?,
        request_id: Id::parse(request)?,
    })
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> { parse_for(args, Family::Index) }
fn parse_for(args: &[OsString], family: Family) -> Result<Parsed, Error> {
    if args.len() > 7 {
        return Err(Error::InvalidRequest);
    }
    let mut w = args
        .iter()
        .map(|v| v.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let json = w.last() == Some(&"--json");
    if json {
        w.pop();
    }
    let command = match w.as_slice() {
        [command, p] if *command == names(family)[0] => Command::Scope(Id::parse(p)?),
        [command, p, i, g] if *command == names(family)[1] => Command::Prepare {
            project: Id::parse(p)?,
            instance: Id::parse(i)?,
            grant: Id::parse(g)?,
        },
        [command, p, i, r, o, v] if *command == names(family)[2] => {
            let s = git::Start {
                origin: query(p, i, r)?,
                prepare_operation_id: (*o).into(),
                review_id: (*v).into(),
            };
            s.validate()?;
            Command::Start(s)
        }
        [command, p, i, r] if *command == names(family)[3] => Command::Status(query(p, i, r)?),
        [command, p, i, r] if *command == names(family)[4] => Command::Cancel(query(p, i, r)?),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { family, command, json })
}
fn framed(body: p::RequestBody) -> Result<p::Request, Error> {
    let request = p::Request {
        version: p::VERSION,
        request_id: Id::random()?,
        request: body,
    };
    p::encode_request(&request)?;
    Ok(request)
}
pub(super) fn receipt(q: &git::Query, family: Family) -> String {
    format!("Inspect without replay: mrk {} {} {} {} --json\nRequest STOP: mrk {} {} {} {} --json\n",
    names(family)[3], q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
    names(family)[4], q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &git::Query, error: Error, json: bool) -> Vec<u8> { unconfirmed_for(q, error, json, Family::Index) }
fn unconfirmed_for(q: &git::Query, error: Error, json: bool, family: Family) -> Vec<u8> {
    let message="No confirmed acknowledgement. Query/cancel this exact Desktop instance and request. Do not prepare or start a replacement. Restore read access if needed; restart cannot replay or settle the old action.";
    let mut b = if json {
        serde_json::to_vec(&serde_json::json!({"ok":false,"error":error,"request":q,"message":message,"doNotReplay":true})).unwrap_or_default()
    } else {
        format!("{message}\n{}", receipt(q, family)).into_bytes()
    };
    b.push(b'\n');
    b
}
fn output(
    response: &p::Response,
    project: &Id,
    origin: Option<&git::Query>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    output_for(response, project, origin, json, Family::Index)
}
fn output_for(response: &p::Response, project: &Id, origin: Option<&git::Query>, json: bool, family: Family) -> Result<(u8, Vec<u8>), Error> {
    if family == Family::Repository { return super::git_repository::output(response, project, origin, json); }
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let (scope, status) = match (family, &response.response) {
        (Family::Index, p::ResponseBody::GitIndexScope(v)) => { v.validate()?; (Some(v), None) },
        (Family::Index, p::ResponseBody::GitIndexRequest(v)) => { v.validate()?; (None, Some(v)) },
        (Family::Commit, p::ResponseBody::GitCommitScope(v)) => { v.validate()?; (Some(&v.0), None) },
        (Family::Commit, p::ResponseBody::GitCommitRequest(v)) => { v.validate()?; (None, Some(&v.0)) },
        _ => return Err(Error::StateUnknown),
    };
    let (code, human) = match (scope, status, origin) {
        (Some(s), None, None)
            if &s.project_id == project && s.service_instance == response.service_instance =>
        {
            // Validated through the exact family wrapper above.
            let mut text=String::from(if family == Family::Commit { "Local whole-staged-index Commit only. Message and author remain in Desktop; no hooks, signing, branch switch, push or credentials.\n" } else { "Local Git Stage/Unstage permission only; no commit, branch, push, credentials or arbitrary command grant.\n" });
            if let Some(selected) = &s.access.selection {
                text.push_str(&format!(
                    "Last checked: {}. {:?}, {} selected paths, repository revision {}.\n",
                    if s.access.enabled {
                        "allowed once"
                    } else if s.access.consumed {
                        "used; keep the original request"
                    } else {
                        "not allowed"
                    },
                    selected.summary.action,
                    selected.summary.path_count,
                    selected.summary.repository_revision
                ));
                for path in &selected.paths {
                    text.push_str("  ");
                    text.push_str(path);
                    text.push('\n');
                }
                if s.access.enabled {
                    text.push_str(&format!(
                        "Prepare: mrk {} {} {} {} --json\n",
                        names(family)[1],
                        project.as_str(),
                        s.service_instance.as_str(),
                        s.access
                            .grant_id
                            .as_ref()
                            .ok_or(Error::StateUnknown)?
                            .as_str()
                    ));
                }
            } else {
                text.push_str(if family == Family::Commit { "After a successful Git check, review all staged paths and the commit draft in Desktop, then explicitly Allow one agent commit.\n" } else { "Select paths after a successful Git check in Desktop, then explicitly Allow one agent index change.\n" });
            }
            (0, text)
        }
        (None, Some(s), Some(q))
            if &s.origin == q && q.service_instance == response.service_instance =>
        {
            // Validated through the exact family wrapper above.
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
                "{:?} — {:?}, {} selected paths; settlement {:?}.\n{}",
                s.selection.action,
                s.state,
                s.selection.path_count,
                s.settlement,
                receipt(q, family)
            );
            if let (Some(op), Some(review)) = (&s.prepare_operation_id, &s.review) {
                text.push_str(&format!("Review {} (index {}, digest {}).\nStart once: mrk {} {} {} {} {} {} --json\n",
                review.review_id,review.expected_index,review.review_digest,names(family)[2],q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),op,review.review_id));
            }
            text.push_str(if s.history_available {
                "Shared history copied this native status. History is not a cleanup receipt.\n"
            } else {
                "Shared history tracking is not confirmed; retain these request IDs.\n"
            });
            (code, text)
        }
        _ => return Err(Error::StateUnknown),
    };
    let mut bytes = if json {
        p::encode_response(response)?
    } else {
        human.into_bytes()
    };
    if json {
        bytes.push(b'\n');
    }
    Ok((code, bytes))
}
pub(super) fn run(args: Vec<OsString>) -> u8 { run_for(args, Family::Index) }
pub(super) fn run_for(args: Vec<OsString>, family: Family) -> u8 {
    let json = args.iter().any(|v| v == "--json");
    let (code, bytes) = parse_for(&args, family)
        .and_then(execute)
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
    if std::io::stdout().write_all(&bytes).is_err() {
        6
    } else {
        code
    }
}
fn execute(options: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let family = options.family;
        let (project, origin, body) = match options.command {
            Command::Scope(p) => (
                p.clone(),
                None,
                match family { Family::Index => p::RequestBody::GitIndexScope(p::ProjectQuery { project_id: p }), Family::Commit => p::RequestBody::GitCommitScope(p::ProjectQuery { project_id: p }), Family::Repository => p::RequestBody::GitRepositoryScope(p::ProjectQuery { project_id: p }) },
            ),
            Command::Prepare {
                project,
                instance,
                grant,
            } => {
                // Mint before the first transport call; every uncertain send
                // exposes this ID. Reconnect never creates another action.
                let q = git::Query {
                    project_id: project.clone(),
                    service_instance: instance,
                    request_id: Id::random()?,
                };
                (
                    project,
                    Some(q.clone()),
                    match family {
                        Family::Index => p::RequestBody::GitIndexPrepare(git::Prepare { origin: q, grant_id: grant }),
                        Family::Commit => p::RequestBody::GitCommitPrepare(git::Prepare { origin: q, grant_id: grant }), Family::Repository => p::RequestBody::GitRepositoryPrepare(git::Prepare { origin: q, grant_id: grant }),
                    },
                )
            }
            Command::Start(s) => (
                s.origin.project_id.clone(),
                Some(s.origin.clone()),
                match family { Family::Index => p::RequestBody::GitIndexStart(s), Family::Commit => p::RequestBody::GitCommitStart(s), Family::Repository => p::RequestBody::GitRepositoryStart(s) },
            ),
            Command::Status(q) => (
                q.project_id.clone(),
                Some(q.clone()),
                match family { Family::Index => p::RequestBody::GitIndexStatus(q), Family::Commit => p::RequestBody::GitCommitStatus(q), Family::Repository => p::RequestBody::GitRepositoryStatus(q) },
            ),
            Command::Cancel(q) => (
                q.project_id.clone(),
                Some(q.clone()),
                match family { Family::Index => p::RequestBody::GitIndexCancel(q), Family::Commit => p::RequestBody::GitCommitCancel(q), Family::Repository => p::RequestBody::GitRepositoryCancel(q) },
            ),
        };
        let result = (|| {
            let path = application_data()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Unavailable)?;
            let response =
                runtime.block_on(crate::installed_cli_ipc::request(&path, &framed(body)?))?;
            output_for(&response, &project, origin.as_ref(), options.json, family)
        })();
        match (result, origin) {
            (Err(e), Some(q)) => Ok((6, unconfirmed_for(&q, e, options.json, family))),
            (other, _) => other,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = options;
        Err(Error::UnsupportedPlatform)
    }
}

#[cfg(test)]
#[path = "installed_cli_git_commit_tests.rs"]
mod commit_tests;

#[cfg(test)]
#[path = "installed_cli_git_index_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "installed_cli_git_repository_tests.rs"]
mod repository_tests;
