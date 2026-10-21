//! Three ID-only calls to the already-open Desktop. It alone prepares and
//! approves each original tool step. No tool/source/download manager lives here.
use super::*;
use crate::service_tool_setup_protocol as tools;

pub(super) const COMMANDS: [&str; 3] = [
    "tool-setup-submit",
    "tool-setup-status",
    "tool-setup-cancel",
];
enum Command {
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
        review: Id,
    },
    Status(tools::Query),
    Cancel(tools::Query),
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
        ["tool-setup-submit", project, instance, grant, review, "--reviewed"] => Command::Submit {
            project: Id::parse(project)?,
            instance: Id::parse(instance)?,
            grant: Id::parse(grant)?,
            review: Id::parse(review)?,
        },
        [kind @ ("tool-setup-status" | "tool-setup-cancel"), project, instance, request] => {
            let q = tools::Query {
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
fn receipt(q: &tools::Query) -> String {
    format!("Request {}\nCheck: mrk tool-setup-status {} {} {} --json\nStop: mrk tool-setup-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &tools::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"Tool setup request outcome is not confirmed. Keep this request ID; check its status or cancel. Do not submit again."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "Tool setup request outcome is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &tools::Query,
    submitted: Option<(&Id, &Id)>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::ToolSetupRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted
            .is_some_and(|(grant, review)| &status.grant_id != grant || &status.review_id != review)
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.state {
        tools::State::Unknown => 6,
        tools::State::Refused
        | tools::State::Cancelled
        | tools::State::Expired
        | tools::State::Failed => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "Tool setup request: {:?}; {:?}.\n{}",
            status.state,
            status.settlement,
            receipt(q)
        );
        text.push_str("Only the exact Desktop-approved tool step is delegated. Doctor uses the confirmed draft copy. Acquisition stages files only; protected-copy publication is not catalogue selection or build readiness. Keep the original IDs; never replay a lost result.\n");
        text.push_str(&format!(
            "Reviewed step: {:?} ({:?}).\n",
            status.review.kind, status.review.platform
        ));
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
                review,
            } => {
                let q = tools::Query {
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
                    Some((grant.clone(), review.clone())),
                    p::RequestBody::ToolSetupSubmit(tools::Submit {
                        origin: q,
                        grant_id: grant,
                        review_id: review,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, p::RequestBody::ToolSetupStatus(q)),
            Command::Cancel(q) => (q.clone(), None, p::RequestBody::ToolSetupCancel(q)),
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
            output(
                &response,
                &q,
                submitted.as_ref().map(|(a, b)| (a, b)),
                options.json,
            )
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
#[path = "installed_cli_tool_setup_tests.rs"]
mod tests;
