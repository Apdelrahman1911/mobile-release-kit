//! IDs-only use of the existing Desktop GitHub owners. No token, URL, draft,
//! provider arguments or alternative native executor. Each actual Prepare or
//! mutation requires its distinct MAIN-issued one-use permission.
use super::*;
use crate::service_github_action_protocol as github;

pub(super) const COMMANDS: [&str; 3] = ["github-submit", "github-status", "github-cancel"];
enum Command {
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
    },
    Status(github::Query),
    Cancel(github::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first()
        .and_then(|v| v.to_str())
        .is_some_and(|v| COMMANDS.contains(&v))
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    let mut words: Vec<&str> = args
        .iter()
        .map(|v| v.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<_, _>>()?;
    if words.iter().any(|v| v.len() > 64) {
        return Err(Error::InvalidRequest);
    }
    let json = words.last() == Some(&"--json");
    if json {
        words.pop();
    }
    let command = match words.as_slice() {
        ["github-submit", project, instance, grant, "--reviewed"] => Command::Submit {
            project: Id::parse(project)?,
            instance: Id::parse(instance)?,
            grant: Id::parse(grant)?,
        },
        [kind @ ("github-status" | "github-cancel"), project, instance, request] => {
            let q = github::Query {
                project_id: Id::parse(project)?,
                service_instance: Id::parse(instance)?,
                request_id: Id::parse(request)?,
            };
            if *kind == COMMANDS[1] {
                Command::Status(q)
            } else {
                Command::Cancel(q)
            }
        }
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn receipt(q: &github::Query) -> String {
    format!("Request {}\nCheck: mrk github-status {} {} {} --json\nStop: mrk github-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &github::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"The original GitHub action is not confirmed. Keep this request ID; check its status or cancel. Do not submit again."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "The original GitHub action is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &github::Query,
    submitted: Option<&Id>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::GitHubActionRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted.is_some_and(|grant| &status.grant_id != grant)
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.state {
        github::State::Unknown => 6,
        github::State::Refused | github::State::Cancelled => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "GitHub action: {:?}; {:?}.\n{}",
            status.state,
            status.settlement,
            receipt(q)
        );
        text.push_str(&format!(
            "Original effect: {:?}. This observation grants no other action.\n",
            status.effect
        ));
        match status.review.kind() {
            github::Kind::ActivityOverview => {
                text.push_str("One historical Activity overview; no write, automatic refresh, current-head/CI proof, jobs, logs or artifacts.
");
                if let Some(snapshot) = &status.snapshot {
                    text.push_str(&format!("Observed {} · account {} · repository {}. Use --json for all compact PR/run IDs and states.\n", snapshot.observed_at, snapshot.account_id, snapshot.repository_id));
                }
            }
            github::Kind::SetupReconcile => text.push_str("This GET-only check observes the exact original setup intent. It sends no new publication request and cannot prove that an uncertain original was never sent.\n"),
            github::Kind::SetupPublish => text.push_str("This request uses the reviewed five-file setup only. A sent create/PR request can trigger repository CI; STOP does not undo it. Counter setup is not included.\n"),
            github::Kind::PreflightDispatch | github::Kind::ReleaseDispatch => text.push_str("One reviewed workflow request. It may run project code and existing workflow privileges; accepted is not CI/release success. Stop does not cancel a GitHub run.\n"),
            github::Kind::CounterCreate => text.push_str("Only the reviewed FIRST counter creation. No allocation, reset, enrollment, protection change or Store request. A sent ref operation is not undone by Stop.\n"),
            k if k.dispatch_family() => text.push_str("One separately approved original read/prepare. Its compact result is historical DATA, not the next action's consent. Check the original Desktop panel; never auto-submit a dispatch/create.\n"),
            _ => {}
        }
        text.push_str("A returned request does not mean CI passed or grant another operation. Use the original Desktop recovery surface for uncertainty; never resubmit automatically.\n");
        text.into_bytes()
    };
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
        let (q, submitted, body) = match options.command {
            Command::Submit {
                project,
                instance,
                grant,
            } => {
                let q = github::Query {
                    project_id: project,
                    service_instance: instance,
                    request_id: Id::random()?,
                };
                // Public correlation only, emitted BEFORE the first transport
                // call. Even a lost socket/ACK never needs another Submit ID.
                std::io::stderr()
                    .write_all(receipt(&q).as_bytes())
                    .map_err(|_| Error::Unavailable)?;
                (
                    q.clone(),
                    Some(grant.clone()),
                    p::RequestBody::GitHubActionSubmit(github::Submit {
                        origin: q,
                        grant_id: grant,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, p::RequestBody::GitHubActionStatus(q)),
            Command::Cancel(q) => (q.clone(), None, p::RequestBody::GitHubActionCancel(q)),
        };
        let result = (|| {
            let path = application_data()?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Unavailable)?;
            let request = p::Request {
                version: p::VERSION,
                request_id: Id::random()?,
                request: body,
            };
            let response = rt.block_on(crate::installed_cli_ipc::request(&path, &request))?;
            output(&response, &q, submitted.as_ref(), options.json)
        })();
        match result {
            Ok(v) => Ok(v),
            Err(e) => Ok((6, unconfirmed(&q, e, options.json))),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = options;
        Err(Error::UnsupportedPlatform)
    }
}

#[cfg(test)]
#[path = "installed_cli_github_action_tests.rs"]
mod tests;
