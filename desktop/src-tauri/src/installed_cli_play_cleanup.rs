//! IDs-only calls to the same Desktop cleanup owner. No raw edit ID, secret,
//! workflow/ref override, local decryptor, allocation or provider implementation.
use super::*;
use crate::service_play_cleanup_protocol as cleanup;

pub(super) const COMMANDS: [&str; 3] = [
    "play-cleanup-submit",
    "play-cleanup-status",
    "play-cleanup-cancel",
];
enum Command {
    Submit {
        project: Id,
        instance: Id,
        consent: Id,
    },
    Status(cleanup::Query),
    Cancel(cleanup::Query),
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
        ["play-cleanup-submit", project, instance, consent, "--reviewed"] => Command::Submit {
            project: Id::parse(project)?,
            instance: Id::parse(instance)?,
            consent: Id::parse(consent)?,
        },
        [kind @ ("play-cleanup-status" | "play-cleanup-cancel"), project, instance, request] => {
            let q = cleanup::Query {
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
fn receipt(q: &cleanup::Query) -> String {
    format!("Request {}\nCheck: mrk play-cleanup-status {} {} {} --json\nStop: mrk play-cleanup-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &cleanup::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"Hosted cleanup dispatch outcome is not confirmed. Keep this request ID; check its status or cancel. Do not submit again; an ACK does not confirm cleanup."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "Hosted cleanup dispatch outcome is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &cleanup::Query,
    submitted: Option<&Id>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::PlayCleanupRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted.is_some_and(|consent| &status.consent_id != consent)
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.state {
        cleanup::State::Unknown => 6,
        cleanup::State::Refused | cleanup::State::Cancelled | cleanup::State::Expired => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "Hosted cleanup: {:?}; {:?}.\n{}",
            status.state,
            status.settlement,
            receipt(q)
        );
        text.push_str(&format!(
            "Dispatch effect: {:?}. No publication is authorized.\n",
            status.effect
        ));
        text.push_str("A GitHub ACK is not cleanup confirmation. Use Desktop's explicit journal observation; never automatically resubmit.\n");
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
                consent,
            } => {
                let q = cleanup::Query {
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
                    Some(consent.clone()),
                    p::RequestBody::PlayCleanupSubmit(cleanup::Submit {
                        origin: q,
                        consent_id: consent,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, p::RequestBody::PlayCleanupStatus(q)),
            Command::Cancel(q) => (q.clone(), None, p::RequestBody::PlayCleanupCancel(q)),
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
#[path = "installed_cli_play_cleanup_tests.rs"]
mod tests;
