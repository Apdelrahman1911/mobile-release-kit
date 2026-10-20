//! Fixed Prepare / Start / Status / Cancel on the running Desktop. No Python,
//! executable, native owner, tool capability or synthetic window is created.
use super::*;
use crate::agent_android_build as build;

enum Command {
    Prepare { project: Id, revision: u64 },
    Start(build::Start),
    Status(build::Query),
    Cancel(build::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first().is_some_and(|v| {
        matches!(
            v.to_str(),
            Some(
                "android-build-prepare"
                    | "android-build-start"
                    | "android-build-status"
                    | "android-build-cancel"
            )
        )
    })
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 7 {
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
    fn query(p: &str, i: &str, r: &str) -> Result<build::Query, Error> {
        Ok(build::Query {
            project_id: Id::parse(p)?,
            service_instance: Id::parse(i)?,
            request_id: Id::parse(r)?,
        })
    }
    let command = match words.as_slice() {
        ["android-build-prepare", project, revision] => {
            if revision.is_empty()
                || revision.len() > 20
                || revision.starts_with('0')
                || !revision.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(Error::InvalidRequest);
            }
            Command::Prepare {
                project: Id::parse(project)?,
                revision: revision.parse().map_err(|_| Error::InvalidRequest)?,
            }
        }
        ["android-build-start", project, instance, request, operation, generation] => {
            Command::Start(build::Start {
                origin: query(project, instance, request)?,
                operation_id: Id::parse(operation)?,
                owner_generation: Id::parse(generation)?,
            })
        }
        ["android-build-status", project, instance, request] => {
            Command::Status(query(project, instance, request)?)
        }
        ["android-build-cancel", project, instance, request] => {
            Command::Cancel(query(project, instance, request)?)
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
    p::encode_request(&request)?;
    Ok(request) // Limit includes the complete envelope.
}
fn receipt(q: &build::Query) -> String {
    format!("Inspect without replay: mrk android-build-status {} {} {} --json\nRequest STOP: mrk android-build-cancel {} {} {} --json\n",
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
pub(super) fn human(s: &build::Status) -> String {
    use build::RequestState as S;
    let description = match s.request_state {
        S::Queued => {
            "Queued for the Desktop's exact saved-input preparation. No Start is requested."
        }
        S::Preparing => "Original preparation is in progress. Do not prepare again.",
        S::OriginalAvailable => "The same original Android operation is linked below.",
        S::RefusedBeforePreparation => {
            "Desktop refused preparation. This request will not be replayed."
        }
        S::CancelledBeforePreparation => {
            "Cancelled before preparation. This request will not be replayed."
        }
        S::Expired => "Start authorization expired. This request will not be replayed.",
        S::AdmissionUnknown => {
            "Original admission is unconfirmed. Preserve this request; do not repeat the action."
        }
    };
    let mut text = format!(
        "{description}\n{}Saved configuration: {} bytes / {}\nSaved version: {} ({}) / {}\n",
        receipt(&s.origin),
        s.review.saved_config.bytes,
        s.review.saved_config.sha256,
        s.review.saved_version.name,
        s.review.saved_version.build,
        s.review.saved_version.sha256
    );
    text.push_str("Scope: existing Android build + structure/version inspection. Project code may read/write files, use network or sign itself; no toolkit signing, credentials, Store upload or release approval is granted.\n");
    if let Some(op) = &s.operation {
        text.push_str(&format!(
            "Operation {} / {} · {:?} · {:?}\nStart: {:?}\n",
            op.operation_id.as_str(),
            op.owner_generation.as_str(),
            op.state,
            op.settlement,
            s.start_state
        ));
        if s.request_state == S::OriginalAvailable
            && s.start_state == build::StartState::NotRequested
            && op.state == p::OperationState::Prepared
            && op.settlement == p::Settlement::Pending
        {
            text.push_str(&format!("Start once, only if this matches your Desktop approval:\nmrk android-build-start {} {} {} {} {} --json\n",
                s.origin.project_id.as_str(), s.origin.service_instance.as_str(), s.origin.request_id.as_str(), op.operation_id.as_str(), op.owner_generation.as_str()));
        }
        if let Some(result) = &op.result {
            text.push_str(&format!("Historical artifact observation: {} bytes / {}\n{} findings (completion is not PASS or release readiness).\n", result.artifact.size, result.artifact.sha256, result.summary.total));
            for (status, count) in &result.summary.counts {
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
    query: &build::Query,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    let s = match &response.response {
        p::ResponseBody::AndroidBuildRequest(s)
            if s.origin == *query && response.service_instance == query.service_instance =>
        {
            s
        }
        p::ResponseBody::Error(e) => return Err(*e),
        _ => return Err(Error::StateUnknown),
    };
    s.validate()?;
    let code = if s.request_state == build::RequestState::AdmissionUnknown
        || s.operation
            .as_ref()
            .is_some_and(|o| o.settlement == p::Settlement::Unknown)
    {
        6
    } else if matches!(
        s.request_state,
        build::RequestState::RefusedBeforePreparation
            | build::RequestState::CancelledBeforePreparation
            | build::RequestState::Expired
    ) || s.operation.as_ref().is_some_and(|o| {
        matches!(
            o.state,
            p::OperationState::Failed | p::OperationState::Cancelled
        )
    }) {
        3
    } else {
        0
    };
    // Zero acknowledges DATA or a known completed observation, never PASS.
    let mut bytes = if json {
        p::encode_response(response)?
    } else {
        human(s).into_bytes()
    };
    if json {
        bytes.push(b'\n');
    }
    Ok((code, bytes))
}
fn unconfirmed(query: &build::Query, error: Error, json: bool) -> Vec<u8> {
    let message = "No confirmed acknowledgement. Query/cancel this exact Desktop instance and request; never prepare or start a replacement action. Enable read access if needed. A restarted Desktop cannot replay or settle it.";
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
        6
    } else {
        code
    }
}
fn execute(options: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let (query, body, changes) = match options.command {
            Command::Status(q) => (q.clone(), p::RequestBody::AndroidBuildStatus(q), false),
            Command::Cancel(q) => (q.clone(), p::RequestBody::AndroidBuildCancel(q), false),
            Command::Start(input) => (
                input.origin.clone(),
                p::RequestBody::AndroidBuildStart(input),
                true,
            ),
            Command::Prepare { project, revision } => {
                let info = runtime.block_on(crate::installed_cli_ipc::request(
                    &path,
                    &framed(p::RequestBody::Info(p::Empty {}))?,
                ))?;
                match info.response {
                    p::ResponseBody::Info(_) => {}
                    p::ResponseBody::Error(e) => return Err(e),
                    _ => return Err(Error::StateUnknown),
                }
                let q = build::Query {
                    service_instance: info.service_instance,
                    project_id: project,
                    request_id: Id::random()?,
                };
                let input = build::Prepare {
                    service_instance: q.service_instance.clone(),
                    project_id: q.project_id.clone(),
                    request_id: q.request_id.clone(),
                    expected_observation_revision: revision,
                };
                input.validate()?;
                (q, p::RequestBody::AndroidBuildPrepare(input), true)
            }
        };
        let request = framed(body)?;
        if changes {
            // Public correlation flushed BEFORE the first possible write. A
            // lost socket/ACK never forces a new identity or implicit Start.
            let mut stderr = std::io::stderr().lock();
            stderr
                .write_all(receipt(&query).as_bytes())
                .and_then(|_| stderr.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = runtime
            .block_on(crate::installed_cli_ipc::request(&path, &request))
            .and_then(|r| output(&r, &query, options.json));
        Ok(result.unwrap_or_else(|e| (6, unconfirmed(&query, e, options.json))))
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
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn exact_prepare_and_start_are_separate_no_arbitrary_configuration_or_commands() {
        let p = "a".repeat(32);
        let i = "b".repeat(32);
        let r = "c".repeat(32);
        let op = "d".repeat(32);
        let gen = "e".repeat(32);
        assert!(parse(&args(&["android-build-prepare", &p, "1", "--json"])).is_ok());
        assert!(parse(&args(&["android-build-start", &p, &i, &r, &op, &gen])).is_ok());
        for verb in ["android-build-status", "android-build-cancel"] {
            assert!(parse(&args(&[verb, &p, &i, &r])).is_ok());
        }
        for value in ["0", "01", "-1", "1.0", "18446744073709551616"] {
            assert!(parse(&args(&["android-build-prepare", &p, value])).is_err());
        }
        for flag in ["--start", "--sign", "--stdin", "--command", "--root"] {
            assert!(parse(&args(&["android-build-prepare", &p, "1", flag])).is_err());
        }
        assert!(parse(&args(&["android-build-start", &p, &i, &r])).is_err());
    }
    #[test]
    fn lost_ack_preserves_exact_correlation_and_whole_frame_stays_bounded() {
        let q = build::Query {
            project_id: Id::parse(&"a".repeat(32)).unwrap(),
            service_instance: Id::parse(&"b".repeat(32)).unwrap(),
            request_id: Id::parse(&"c".repeat(32)).unwrap(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
        assert_eq!(value["request"], serde_json::to_value(&q).unwrap());
        assert_eq!(value["doNotReplay"], true);
        assert!(receipt(&q).contains("android-build-status"));
        assert!(receipt(&q).contains("android-build-cancel"));
        let frame = framed(p::RequestBody::AndroidBuildStart(build::Start {
            origin: q,
            operation_id: Id::parse(&"d".repeat(32)).unwrap(),
            owner_generation: Id::parse(&"e".repeat(32)).unwrap(),
        }))
        .unwrap();
        assert!(p::encode_request(&frame).unwrap().len() <= p::REQUEST_BYTES);
    }
}
