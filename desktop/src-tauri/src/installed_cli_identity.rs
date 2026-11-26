//! Closed identity proposal frontend, a child of installed_cli. It submits
//! DATA to the already running Desktop and never calls native EditOwner/GUI.
//! There is intentionally no CLI Prepare, Apply, executable or endpoint flag.
use super::*;
use crate::agent_identity_requests as requests;
use std::io::{IsTerminal, Read};

enum Command {
    Submit { project: Id, revision: u64 },
    Query(requests::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first()
        .is_some_and(|arg| arg == "identity-request" || arg == "identity-request-status")
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 5 {
        return Err(Error::InvalidRequest);
    }
    let mut words = args
        .iter()
        .map(|arg| arg.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let json = words.last() == Some(&"--json");
    if json {
        words.pop();
    }
    let command = match words.as_slice() {
        ["identity-request", project, revision, "--stdin"] => {
            if revision.is_empty()
                || revision.len() > 20
                || revision.starts_with('0')
                || !revision.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::InvalidRequest);
            }
            Command::Submit {
                project: Id::parse(project)?,
                revision: revision.parse().map_err(|_| Error::InvalidRequest)?,
            }
        }
        ["identity-request-status", project, instance, intent] => Command::Query(requests::Query {
            service_instance: Id::parse(instance)?,
            project_id: Id::parse(project)?,
            intent_id: Id::parse(intent)?,
        }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn read_change(reader: impl Read) -> Result<requests::Change, Error> {
    let mut bytes = Vec::new();
    reader
        .take((p::REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    if bytes.is_empty() || bytes.len() > p::REQUEST_BYTES {
        return Err(Error::InvalidRequest);
    }
    // Deserialize directly, retaining duplicate-field rejection. A value-only
    // conversion must not silently collapse two conflicting desired IDs.
    let change: requests::Change =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    change.validate()?;
    Ok(change)
}
fn framed(request: p::RequestBody) -> Result<p::Request, Error> {
    let request = p::Request {
        version: p::VERSION,
        request_id: Id::random()?,
        request,
    };
    // The COMPLETE protocol envelope, not merely stdin, has the same 4096 cap
    // as the original server. Nothing is sent if this final check refuses.
    p::encode_request(&request)?;
    Ok(request)
}
pub(super) fn human(status: &requests::IntentStatus) -> String {
    use requests::IntentState as S;
    let description = match status.state {
        S::Queued => "Queued for Desktop review. No edit is authorized by this receipt.",
        S::DesktopReview => "Desktop admission is in progress. Do not submit this change again.",
        S::OriginalSidAvailable => "Original Desktop session linked. Its status is separate; this is not a completed edit.",
        S::Declined => "Desktop declined this proposal. This request ID will not run again.",
        S::Expired => "The proposal expired before Desktop admission. This request ID will not run again.",
        S::RefusedBeforeClaim => "The original owner returned a refusal before claiming this proposal. This request ID will not run again.",
        S::AdmissionUnconfirmed => "Admission could not be confirmed. Do not replay; inspect the original Desktop task.",
    };
    let mut text = format!(
        "Intent {} · Desktop {}\n{description}\n",
        status.intent_id.as_str(),
        status.service_instance.as_str()
    );
    if let Some(operation) = &status.operation_id {
        text.push_str(&format!("Original session: {}\nOperation history may be unavailable; a missing row or lost link does not settle the original work.\n", operation.as_str()));
    }
    text
}
fn unconfirmed(query: &requests::Query, error: Error, json: bool) -> Vec<u8> {
    let message = "Request acknowledgement unavailable. Do not submit as a new intent. Query this exact Desktop instance/request or inspect the original Desktop task.";
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({
            "version":p::VERSION, "ok":false, "error":error, "message":message,
            "intent":query, "admission":"unconfirmed", "doNotReplay":true,
        }))
        .unwrap_or_else(|_| {
            b"{\"ok\":false,\"admission\":\"unconfirmed\",\"doNotReplay\":true}".to_vec()
        })
    } else {
        format!(
            "{message}\n{}\nDesktop {} · intent {} · project {}",
            error.message(),
            query.service_instance.as_str(),
            query.intent_id.as_str(),
            query.project_id.as_str()
        )
        .into_bytes()
    };
    bytes.push(b'\n');
    bytes
}
fn output(
    response: &p::Response,
    query: &requests::Query,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    let status = match &response.response {
        p::ResponseBody::IdentityIntent(status)
            if status.intent_id == query.intent_id
                && status.service_instance == query.service_instance
                && status.project_id == query.project_id =>
        {
            status
        }
        p::ResponseBody::Error(error) => return Err(*error),
        _ => return Err(Error::StateUnknown),
    };
    status.validate()?;
    let code = if status.state == requests::IntentState::AdmissionUnconfirmed {
        6
    } else {
        0
    };
    let mut bytes = if json {
        p::encode_response(response)?
    } else {
        human(status).into_bytes()
    };
    if json {
        bytes.push(b'\n');
    }
    Ok((code, bytes))
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|arg| arg == "--json");
    let result = parse(&args).and_then(execute);
    let (code, bytes) = result.unwrap_or_else(|error| (exit_code(error), error_bytes(error, json)));
    if std::io::stdout().write_all(&bytes).is_err() {
        return 6;
    }
    code
}
fn execute(options: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        match options.command {
            Command::Query(query) => {
                let request = framed(p::RequestBody::IdentityIntent(query.clone()))?;
                let response =
                    runtime.block_on(crate::installed_cli_ipc::request(&path, &request))?;
                output(&response, &query, options.json)
            }
            Command::Submit { project, revision } => {
                // A pipe/file is explicit. Never prompt for secrets or start a
                // half-entered request while the caller is at a terminal.
                if std::io::stdin().is_terminal() {
                    return Err(Error::InvalidRequest);
                }
                let change = read_change(std::io::stdin().lock())?;
                // Safe read handshake obtains the actual per-launch instance.
                // A restart between these calls conflicts; it cannot enqueue
                // a proposal into an unapproved replacement host.
                let info = runtime.block_on(crate::installed_cli_ipc::request(
                    &path,
                    &framed(p::RequestBody::Info(p::Empty {}))?,
                ))?;
                match info.response {
                    p::ResponseBody::Info(_) => {}
                    p::ResponseBody::Error(error) => return Err(error),
                    _ => return Err(Error::StateUnknown),
                }
                let query = requests::Query {
                    service_instance: info.service_instance,
                    project_id: project,
                    intent_id: Id::random()?,
                };
                let input = requests::Submit {
                    service_instance: query.service_instance.clone(),
                    project_id: query.project_id.clone(),
                    intent_id: query.intent_id.clone(),
                    expected_observation_revision: revision,
                    change,
                };
                input.validate()?;
                let request = framed(p::RequestBody::IdentitySubmit(input))?;
                // Publish only public correlation BEFORE sending. A killed or
                // disconnected CLI can still inspect this exact intent, never
                // guess a new ID. Output failure refuses before transmission.
                let receipt = format!(
                    "Inspect without replay: mrk identity-request-status {} {} {} --json\n",
                    query.project_id.as_str(),
                    query.service_instance.as_str(),
                    query.intent_id.as_str()
                );
                let mut stderr = std::io::stderr().lock();
                stderr
                    .write_all(receipt.as_bytes())
                    .and_then(|_| stderr.flush())
                    .map_err(|_| Error::StateUnknown)?;
                drop(stderr);
                let result = runtime
                    .block_on(crate::installed_cli_ipc::request(&path, &request))
                    .and_then(|response| output(&response, &query, options.json));
                // No transport/serialization failure is a native negative
                // admission receipt. Never automatically retry this request.
                Ok(result.unwrap_or_else(|error| (6, unconfirmed(&query, error, options.json))))
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = options;
        Err(Error::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }
    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHANGE: &[u8] = br#"{"selection":{"platform":"android","target":":app","project":null},"desiredIdentity":"com.example.fixture","identityIntent":"new-application"}"#;
    #[test]
    fn closed_cli_arguments_do_not_accept_apply_identity_values_or_other_origins() {
        assert!(parse(&args(&["identity-request", ID, "3", "--stdin", "--json"])).is_ok());
        assert!(parse(&args(&["identity-request-status", ID, ID, ID, "--json"])).is_ok());
        for input in [
            args(&["identity-request", ID, "3", "com.example.in.argv"]),
            args(&["identity-request", ID, "03", "--stdin"]),
            args(&["identity-request", ID, "0", "--stdin"]),
            args(&["identity-request", ID, "3", "--apply"]),
            args(&[
                "identity-request",
                ID,
                "3",
                "--endpoint",
                "private sentinel",
            ]),
        ] {
            assert!(parse(&input).is_err());
        }
    }
    #[test]
    fn stdin_and_complete_request_envelope_are_bounded_before_send() {
        let change = read_change(CHANGE).unwrap();
        assert!(read_change(&vec![b' '; p::REQUEST_BYTES + 1][..]).is_err());
        assert!(
            read_change(br#"{"root":"/inert","credentials":"private sentinel"}"#.as_slice())
                .is_err()
        );
        let id = Id::parse(ID).unwrap();
        let request = framed(p::RequestBody::IdentitySubmit(requests::Submit {
            service_instance: id.clone(),
            project_id: id.clone(),
            intent_id: id,
            expected_observation_revision: 3,
            change,
        }))
        .unwrap();
        let encoded = p::encode_request(&request).unwrap();
        assert!(encoded.len() <= p::REQUEST_BYTES);
        assert!(matches!(
            p::decode_request(&encoded).unwrap().request,
            p::RequestBody::IdentitySubmit(_)
        ));
    }
    #[test]
    fn lost_ack_keeps_exact_instance_and_intent_without_native_success_claim() {
        let id = Id::parse(ID).unwrap();
        let query = requests::Query {
            service_instance: id.clone(),
            project_id: id.clone(),
            intent_id: id,
        };
        let bytes = unconfirmed(&query, Error::Unavailable, true);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["admission"], "unconfirmed");
        assert_eq!(value["doNotReplay"], true);
        assert_eq!(value["intent"]["intentId"], ID);
        assert_eq!(value["intent"]["serviceInstance"], ID);
        assert!(value.get("operationId").is_none() && value.get("settled").is_none());
    }
}
