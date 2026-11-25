//! Fixed local-check verbs on the original installed service. No Python,
//! executable, configuration payload, native owner or window is constructed.
use super::*;
use crate::agent_local_checks as local;

enum Command {
    Submit { project: Id, revision: u64 },
    Status(local::Query),
    Cancel(local::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first().is_some_and(|a| {
        a == "local-check" || a == "local-check-status" || a == "local-check-cancel"
    })
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 5 {
        return Err(Error::InvalidRequest);
    }
    let mut words = args
        .iter()
        .map(|s| s.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let json = words.last() == Some(&"--json");
    if json {
        words.pop();
    }
    let command = match words.as_slice() {
        ["local-check", project, revision] => {
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
        [verb @ ("local-check-status" | "local-check-cancel"), project, instance, request] => {
            let q = local::Query {
                project_id: Id::parse(project)?,
                service_instance: Id::parse(instance)?,
                request_id: Id::parse(request)?,
            };
            if *verb == "local-check-status" {
                Command::Status(q)
            } else {
                Command::Cancel(q)
            }
        }
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
    p::encode_request(&request)?; // Whole frame, not merely the inner fields.
    Ok(request)
}
fn receipt(q: &local::Query) -> String {
    format!("Inspect without replay: mrk local-check-status {} {} {} --json\nRequest STOP: mrk local-check-cancel {} {} {} --json\n",
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
pub(super) fn human(s: &local::Status) -> String {
    use local::RequestState as S;
    let description = match s.request_state {
        S::Queued => "Queued for the already-authorized Desktop local check; do not submit again.",
        S::Admitting => "Original Desktop admission is in progress; do not submit again.",
        S::OriginalAvailable => "The same original Desktop operation is linked below.",
        S::RefusedBeforeAdmission => "Desktop refused before original admission. This request will not be replayed.",
        S::CancelledBeforeAdmission => "Cancelled before original admission. This request will not be replayed.",
        S::Expired => "The one-use Desktop permission expired before admission. This request will not be replayed.",
        S::AdmissionUnknown => "Admission is unconfirmed. Preserve this request and inspect Desktop; do not repeat the action.",
    };
    let mut text = format!("{description}\n{}", receipt(&s.origin));
    if let Some(op) = &s.operation {
        // Codes only: these are copies from actual native retirement, not a
        // second observer or a substitute for the original cleanup owner.
        text.push_str(&format!(
            "Operation {} · {:?} · {:?}\n",
            op.operation_id.as_str(),
            op.state,
            op.settlement
        ));
        if let Some(report) = &op.result {
            text.push_str(&format!(
                "Checks completed (not release approval): {} total, {} shown, {} omitted.\n",
                report.summary.total, report.summary.shown, report.summary.omitted
            ));
            for (status, count) in &report.summary.counts {
                text.push_str(&format!("{status:?}: {count}\n"));
            }
        }
        if op.settlement == p::Settlement::Unknown {
            text.push_str("Native cleanup is unknown; history or a new client cannot clear it.\n");
        }
    }
    if !s.history_available {
        text.push_str("Shared history may not yet contain this original status; absence never proves settlement.\n");
    }
    text
}
fn output(
    response: &p::Response,
    query: &local::Query,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    let status = match &response.response {
        p::ResponseBody::LocalCheck(s)
            if s.origin == *query && response.service_instance == query.service_instance =>
        {
            s
        }
        p::ResponseBody::Error(error) => return Err(*error),
        _ => return Err(Error::StateUnknown),
    };
    status.validate()?;
    let code = if status.request_state == local::RequestState::AdmissionUnknown
        || status
            .operation
            .as_ref()
            .is_some_and(|p| p.settlement == p::Settlement::Unknown)
    {
        6
    } else if matches!(
        status.request_state,
        local::RequestState::RefusedBeforeAdmission
            | local::RequestState::CancelledBeforeAdmission
            | local::RequestState::Expired
    ) || status.operation.as_ref().is_some_and(|p| {
        matches!(
            p.state,
            p::OperationState::Failed | p::OperationState::Cancelled
        )
    }) {
        3
    } else {
        0
    };
    // Exit 0 acknowledges the request/finished observation, not PASS/readiness.
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
fn unconfirmed(query: &local::Query, error: Error, json: bool) -> Vec<u8> {
    let message = "No confirmed acknowledgement. Query/cancel this exact Desktop instance and request; never resubmit as a new action. Enable read access to inspect it if needed. A restarted Desktop cannot replay or settle it.";
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({"ok":false,"error":error,"message":message,"request":query,"doNotReplay":true}))
            .unwrap_or_else(|_| b"{\"ok\":false,\"doNotReplay\":true}".to_vec())
    } else {
        format!("{message}\n{}", receipt(query)).into_bytes()
    };
    bytes.push(b'\n');
    bytes
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let (code, bytes) = parse(&args)
        .and_then(execute)
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
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
        let (query, body, submit) = match options.command {
            Command::Status(q) => (q.clone(), p::RequestBody::LocalCheckStatus(q), false),
            Command::Cancel(q) => (q.clone(), p::RequestBody::LocalCheckCancel(q), false),
            Command::Submit { project, revision } => {
                let info = runtime.block_on(crate::installed_cli_ipc::request(
                    &path,
                    &framed(p::RequestBody::Info(p::Empty {}))?,
                ))?;
                match info.response {
                    p::ResponseBody::Info(_) => {}
                    p::ResponseBody::Error(e) => return Err(e),
                    _ => return Err(Error::StateUnknown),
                }
                let q = local::Query {
                    service_instance: info.service_instance,
                    project_id: project,
                    request_id: Id::random()?,
                };
                let input = local::Submit {
                    service_instance: q.service_instance.clone(),
                    project_id: q.project_id.clone(),
                    request_id: q.request_id.clone(),
                    expected_observation_revision: revision,
                };
                input.validate()?;
                (q, p::RequestBody::LocalCheckSubmit(input), true)
            }
        };
        let request = framed(body)?;
        if submit {
            // Public correlation is flushed BEFORE any action send. Failure
            // here refuses without transmission; no secret/token is printed.
            let mut stderr = std::io::stderr().lock();
            stderr
                .write_all(receipt(&query).as_bytes())
                .and_then(|_| stderr.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = runtime
            .block_on(crate::installed_cli_ipc::request(&path, &request))
            .and_then(|response| output(&response, &query, options.json));
        Ok(result.unwrap_or_else(|error| (6, unconfirmed(&query, error, options.json))))
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
    #[test]
    fn only_three_closed_verbs_and_canonical_observation_numbers() {
        let p = "a".repeat(32);
        let i = "b".repeat(32);
        let r = "c".repeat(32);
        assert!(parse(&args(&["local-check", &p, "1", "--json"])).is_ok());
        for verb in ["local-check-status", "local-check-cancel"] {
            assert!(parse(&args(&[verb, &p, &i, &r])).is_ok());
        }
        for revision in ["0", "01", "-1", "1.0", "18446744073709551616", "1 --shell"] {
            assert!(parse(&args(&["local-check", &p, revision])).is_err());
        }
        assert!(parse(&args(&["local-check", &p, "1", "--stdin"])).is_err());
        assert!(parse(&args(&["local-check", &p, "1", "--root", "/tmp"])).is_err());
    }
    #[test]
    fn lost_ack_output_retains_exact_query_and_cancel_without_fresh_action() {
        let q = local::Query {
            project_id: Id::parse(&"a".repeat(32)).unwrap(),
            service_instance: Id::parse(&"b".repeat(32)).unwrap(),
            request_id: Id::parse(&"c".repeat(32)).unwrap(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
        assert_eq!(value["request"], serde_json::to_value(&q).unwrap());
        assert_eq!(value["doNotReplay"], true);
        assert!(receipt(&q).contains("local-check-status"));
        assert!(receipt(&q).contains("local-check-cancel"));
        let request = framed(p::RequestBody::LocalCheckSubmit(local::Submit {
            service_instance: q.service_instance,
            project_id: q.project_id,
            request_id: q.request_id,
            expected_observation_revision: 1,
        }))
        .unwrap();
        assert!(p::encode_request(&request).unwrap().len() <= p::REQUEST_BYTES);
    }
}
