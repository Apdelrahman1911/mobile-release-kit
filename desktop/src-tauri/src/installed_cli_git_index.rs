//! Closed Stage/Unstage client. Paths come only from the actual Desktop grant;
//! no executable, raw Git command, diff, commit draft or native owner is made.
use super::*;
use crate::service_git_protocol as git;

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
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first().and_then(|s| s.to_str()).is_some_and(|s| {
        matches!(
            s,
            "git-index-scope"
                | "git-index-prepare"
                | "git-index-start"
                | "git-index-status"
                | "git-index-cancel"
        )
    })
}
fn query(project: &str, instance: &str, request: &str) -> Result<git::Query, Error> {
    Ok(git::Query {
        project_id: Id::parse(project)?,
        service_instance: Id::parse(instance)?,
        request_id: Id::parse(request)?,
    })
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
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
        ["git-index-scope", p] => Command::Scope(Id::parse(p)?),
        ["git-index-prepare", p, i, g] => Command::Prepare {
            project: Id::parse(p)?,
            instance: Id::parse(i)?,
            grant: Id::parse(g)?,
        },
        ["git-index-start", p, i, r, o, v] => {
            let s = git::Start {
                origin: query(p, i, r)?,
                prepare_operation_id: (*o).into(),
                review_id: (*v).into(),
            };
            s.validate()?;
            Command::Start(s)
        }
        ["git-index-status", p, i, r] => Command::Status(query(p, i, r)?),
        ["git-index-cancel", p, i, r] => Command::Cancel(query(p, i, r)?),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
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
fn receipt(q: &git::Query) -> String {
    format!("Inspect without replay: mrk git-index-status {} {} {} --json\nRequest STOP: mrk git-index-cancel {} {} {} --json\n",
    q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
fn unconfirmed(q: &git::Query, error: Error, json: bool) -> Vec<u8> {
    let message="No confirmed acknowledgement. Query/cancel this exact Desktop instance and request. Do not prepare or start a replacement. Restore read access if needed; restart cannot replay or settle the old action.";
    let mut b = if json {
        serde_json::to_vec(&serde_json::json!({"ok":false,"error":error,"request":q,"message":message,"doNotReplay":true})).unwrap_or_default()
    } else {
        format!("{message}\n{}", receipt(q)).into_bytes()
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
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let (code, human) = match (&response.response, origin) {
        (p::ResponseBody::GitIndexScope(s), None)
            if &s.project_id == project && s.service_instance == response.service_instance =>
        {
            s.validate()?;
            let mut text=String::from("Local Git Stage/Unstage permission only; no commit, branch, push, credentials or arbitrary command grant.\n");
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
                        "Prepare: mrk git-index-prepare {} {} {} --json\n",
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
                text.push_str("Select paths after a successful Git check in Desktop, then explicitly Allow one agent index change.\n");
            }
            (0, text)
        }
        (p::ResponseBody::GitIndexRequest(s), Some(q))
            if &s.origin == q && q.service_instance == response.service_instance =>
        {
            s.validate()?;
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
                receipt(q)
            );
            if let (Some(op), Some(review)) = (&s.prepare_operation_id, &s.review) {
                text.push_str(&format!("Review {} (index {}, digest {}).\nStart once: mrk git-index-start {} {} {} {} {} --json\n",
                review.review_id,review.expected_index,review.review_digest,q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),op,review.review_id));
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
pub(super) fn run(args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|v| v == "--json");
    let (code, bytes) = parse(&args)
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
        let (project, origin, body) = match options.command {
            Command::Scope(p) => (
                p.clone(),
                None,
                p::RequestBody::GitIndexScope(p::ProjectQuery { project_id: p }),
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
                    p::RequestBody::GitIndexPrepare(git::Prepare {
                        origin: q,
                        grant_id: grant,
                    }),
                )
            }
            Command::Start(s) => (
                s.origin.project_id.clone(),
                Some(s.origin.clone()),
                p::RequestBody::GitIndexStart(s),
            ),
            Command::Status(q) => (
                q.project_id.clone(),
                Some(q.clone()),
                p::RequestBody::GitIndexStatus(q),
            ),
            Command::Cancel(q) => (
                q.project_id.clone(),
                Some(q.clone()),
                p::RequestBody::GitIndexCancel(q),
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
            output(&response, &project, origin.as_ref(), options.json)
        })();
        match (result, origin) {
            (Err(e), Some(q)) => Ok((6, unconfirmed(&q, e, options.json))),
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
#[path = "installed_cli_git_index_tests.rs"]
mod tests;
