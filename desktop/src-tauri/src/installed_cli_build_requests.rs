//! Fixed Prepare / Start / Status / Cancel on the running Desktop. No Python,
//! executable, native owner, tool capability or synthetic window is created.
use super::*;
use crate::{agent_build_requests as build, agent_build_requests::Family};

fn command_name(family: Family, action: &str) -> &'static str {
    match (family, action) {
        (Family::AndroidInspect, "prepare") => "android-build-prepare",
        (Family::AndroidInspect, "start") => "android-build-start",
        (Family::AndroidInspect, "status") => "android-build-status",
        (Family::AndroidInspect, "cancel") => "android-build-cancel",
        (Family::IosArchive, "prepare") => "ios-archive-prepare",
        (Family::IosArchive, "start") => "ios-archive-start",
        (Family::IosArchive, "status") => "ios-archive-status",
        (Family::IosArchive, "cancel") => "ios-archive-cancel",
        _ => unreachable!("fixed internal verb"),
    }
}
pub(super) enum Command {
    Prepare { project: Id, revision: u64 },
    Start(build::Start),
    Status(build::Query),
    Cancel(build::Query),
}
pub(super) struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(family: Family, args: &[OsString]) -> bool {
    args.first()
        .and_then(|v| v.to_str())
        .is_some_and(|v| match family {
            Family::AndroidInspect => matches!(
                v,
                "android-build-prepare"
                    | "android-build-start"
                    | "android-build-status"
                    | "android-build-cancel"
            ),
            Family::IosArchive => matches!(
                v,
                "ios-archive-prepare"
                    | "ios-archive-start"
                    | "ios-archive-status"
                    | "ios-archive-cancel"
            ),
        })
}
pub(super) fn parse(family: Family, args: &[OsString]) -> Result<Parsed, Error> {
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
        [verb, project, revision] if *verb == command_name(family, "prepare") => {
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
        [verb, project, instance, request, operation, generation]
            if *verb == command_name(family, "start") =>
        {
            Command::Start(build::Start {
                origin: query(project, instance, request)?,
                operation_id: Id::parse(operation)?,
                owner_generation: Id::parse(generation)?,
            })
        }
        [verb, project, instance, request] if *verb == command_name(family, "status") => {
            Command::Status(query(project, instance, request)?)
        }
        [verb, project, instance, request] if *verb == command_name(family, "cancel") => {
            Command::Cancel(query(project, instance, request)?)
        }
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
pub(super) fn framed(body: p::RequestBody) -> Result<p::Request, Error> {
    let request = p::Request {
        version: p::VERSION,
        request_id: Id::random()?,
        request: body,
    };
    p::encode_request(&request)?;
    Ok(request) // Limit includes the complete envelope.
}
pub(super) fn receipt(family: Family, q: &build::Query) -> String {
    format!(
        "Inspect without replay: mrk {} {} {} {} --json\nRequest STOP: mrk {} {} {} {} --json\n",
        command_name(family, "status"),
        q.project_id.as_str(),
        q.service_instance.as_str(),
        q.request_id.as_str(),
        command_name(family, "cancel"),
        q.project_id.as_str(),
        q.service_instance.as_str(),
        q.request_id.as_str()
    )
}

fn output(
    response: &p::Response,
    query: &build::Query,
    family: Family,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if response.service_instance != query.service_instance {
        return Err(Error::StateUnknown);
    }
    let (request_state, native, human) = match (&response.response, family) {
        (p::ResponseBody::AndroidBuildRequest(s), Family::AndroidInspect) if s.origin == *query => {
            s.validate()?;
            (
                s.request_state,
                s.operation.as_ref().map(|o| (o.state, o.settlement)),
                android_build::human(s),
            )
        }
        (p::ResponseBody::IosArchiveRequest(s), Family::IosArchive) if s.origin == *query => {
            s.validate()?;
            (
                s.request_state,
                s.operation.as_ref().map(|o| (o.state, o.settlement)),
                ios_archive::human(s),
            )
        }
        (p::ResponseBody::Error(e), _) => return Err(*e),
        _ => return Err(Error::StateUnknown),
    };
    let code = if request_state == build::RequestState::AdmissionUnknown
        || native.is_some_and(|(_, s)| s == p::Settlement::Unknown)
    {
        6
    } else if matches!(
        request_state,
        build::RequestState::RefusedBeforePreparation
            | build::RequestState::CancelledBeforePreparation
            | build::RequestState::Expired
    ) || native
        .is_some_and(|(s, _)| matches!(s, p::OperationState::Failed | p::OperationState::Cancelled))
    {
        3
    } else {
        0
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

pub(super) fn unconfirmed(
    family: Family,
    query: &build::Query,
    error: Error,
    json: bool,
) -> Vec<u8> {
    let message = "No confirmed acknowledgement. Query/cancel this exact Desktop instance and request; never prepare or start a replacement action. Enable read access if needed. A restarted Desktop cannot replay or settle it.";
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({"ok":false,"error":error,"message":message,"request":query,"doNotReplay":true}))
        .unwrap_or_else(|_| b"{\"ok\":false,\"doNotReplay\":true}".to_vec())
    } else {
        format!("{message}\n{}", receipt(family, query)).into_bytes()
    };
    bytes.push(b'\n');
    bytes
}
pub(super) fn run(family: Family, args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let (code, bytes) = parse(family, &args)
        .and_then(|v| execute(family, v))
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
    if std::io::stdout().write_all(&bytes).is_err() {
        6
    } else {
        code
    }
}
fn execute(family: Family, options: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let (query, body, changes) = match options.command {
            Command::Status(q) => (
                q.clone(),
                match family {
                    Family::AndroidInspect => p::RequestBody::AndroidBuildStatus(q),
                    Family::IosArchive => p::RequestBody::IosArchiveStatus(q),
                },
                false,
            ),
            Command::Cancel(q) => (
                q.clone(),
                match family {
                    Family::AndroidInspect => p::RequestBody::AndroidBuildCancel(q),
                    Family::IosArchive => p::RequestBody::IosArchiveCancel(q),
                },
                false,
            ),
            Command::Start(input) => (
                input.origin.clone(),
                match family {
                    Family::AndroidInspect => p::RequestBody::AndroidBuildStart(input),
                    Family::IosArchive => p::RequestBody::IosArchiveStart(input),
                },
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
                (
                    q,
                    match family {
                        Family::AndroidInspect => p::RequestBody::AndroidBuildPrepare(input),
                        Family::IosArchive => p::RequestBody::IosArchivePrepare(input),
                    },
                    true,
                )
            }
        };
        let request = framed(body)?;
        if changes {
            // Public correlation flushed BEFORE the first possible write. A
            // lost socket/ACK never forces a new identity or implicit Start.
            let mut stderr = std::io::stderr().lock();
            stderr
                .write_all(receipt(family, &query).as_bytes())
                .and_then(|_| stderr.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = runtime
            .block_on(crate::installed_cli_ipc::request(&path, &request))
            .and_then(|r| output(&r, &query, family, options.json));
        Ok(result.unwrap_or_else(|e| (6, unconfirmed(family, &query, e, options.json))))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = options;
        Err(Error::UnsupportedPlatform)
    }
}
