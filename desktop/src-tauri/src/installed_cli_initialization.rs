//! ID-only genuine release-project Initialization via running Desktop. The
//! selected draft/toolkit, preview and writer remain with its original owner.
use super::*;
use crate::service_initialization_protocol as c;
pub(super) const COMMANDS: [CommandCapability; 4] = [
    CommandCapability {
        command: "initialization-prepare",
        arguments: &["PROJECT_ID", "OBSERVATION_REVISION"],
        description:
            "Prepare from Desktop's selected valid draft/toolkit; READ does not authorize writes.",
    },
    CommandCapability {
        command: "initialization-apply",
        arguments: &[
            "PROJECT_ID",
            "SERVICE_INSTANCE",
            "REQUEST_ID",
            "SESSION_ID",
            "OWNER_GENERATION",
            "REVISION",
            "PLAN_TOKEN",
            "--reviewed",
        ],
        description:
            "Apply the exact native initialization inventory after separate Desktop consent, once.",
    },
    CommandCapability {
        command: "initialization-status",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Inspect this retained original, not a replay or automatic recovery.",
    },
    CommandCapability {
        command: "initialization-cancel",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Request original STOP; wait for native/caller/history retirement.",
    },
];
enum Command {
    Prepare(Id, u64),
    Apply(c::Apply),
    Query(c::Query, bool),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first()
        .is_some_and(|a| COMMANDS.iter().any(|c| a == c.command))
}
fn query(p: &str, i: &str, q: &str) -> Result<c::Query, Error> {
    Ok(c::Query {
        project_id: Id::parse(p)?,
        service_instance: Id::parse(i)?,
        request_id: Id::parse(q)?,
    })
}
fn original(s: &str, g: &str, r: &str) -> Result<c::Original, Error> {
    Ok(c::Original {
        session_id: Id::parse(s)?,
        owner_generation: Id::parse(g)?,
        revision: Id::parse(r)?,
    })
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 10 {
        return Err(Error::InvalidRequest);
    }
    let mut words = args
        .iter()
        .map(|a| a.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let json = words.last() == Some(&"--json");
    if json {
        words.pop();
    }
    let command = match words.as_slice() {
        ["initialization-prepare", p, r] => {
            let n = r.parse::<u64>().map_err(|_| Error::InvalidRequest)?;
            if n == 0 || n.to_string() != *r {
                return Err(Error::InvalidRequest);
            }
            Command::Prepare(Id::parse(p)?, n)
        }
        ["initialization-status", p, i, q] => Command::Query(query(p, i, q)?, false),
        ["initialization-cancel", p, i, q] => Command::Query(query(p, i, q)?, true),
        ["initialization-apply", p, i, q, s, g, r, t, "--reviewed"] => Command::Apply(c::Apply {
            origin: query(p, i, q)?,
            original: original(s, g, r)?,
            plan_token: Id::parse(t)?,
            reviewed: true,
        }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn framed(body: p::RequestBody) -> Result<p::Request, Error> {
    let r = p::Request {
        version: p::VERSION,
        request_id: Id::random()?,
        request: body,
    };
    p::encode_request(&r)?;
    Ok(r)
}
fn receipt(q: &c::Query) -> String {
    format!("Inspect without replay: mrk initialization-status {} {} {} --json\nRequest STOP: mrk initialization-cancel {} {} {} --json\n",q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
pub(super) fn human(s: &c::Status) -> String {
    let mut out = format!(
        "{}Release-project initialization: {:?}\n",
        receipt(&s.origin),
        s.phase
    );
    if let Some(o) = &s.original {
        out.push_str(&format!(
            "Original {} / {} / {}\n",
            o.session_id.as_str(),
            o.owner_generation.as_str(),
            o.revision.as_str()
        ));
    }
    if let Some(r) = &s.review {
        out.push_str(&format!("Native inventory: {} files ({} create, {} preserve, {} append), {} directories. Toolkit {} @ {}.\n",r.file_count,r.created_files,r.preserved_files,r.appended_files,r.created_directories,r.tooling_repository,r.tooling_sha));
        out.push_str("Inspect the full native inventory in Desktop and separately allow this exact preview.\n");
        if s.permission_available {
            if let Some(o) = &s.original {
                out.push_str(&format!(
                    "mrk initialization-apply {} {} {} {} {} {} {} --reviewed --json\n",
                    s.origin.project_id.as_str(),
                    s.origin.service_instance.as_str(),
                    s.origin.request_id.as_str(),
                    o.session_id.as_str(),
                    o.owner_generation.as_str(),
                    o.revision.as_str(),
                    r.plan_token.as_str()
                ));
            }
        }
    }
    if s.result.as_ref().is_some_and(c::Final::saved) {
        out.push_str("Original native initialization, caller and history settled. Newer Desktop draft remains unchanged.\n");
    }
    out.push_str("Requires running Desktop's explicit valid draft/toolkit. No arbitrary paths or existing-target overwrite; recovery stays in Desktop.\n");
    out
}
fn output(response: &p::Response, q: &c::Query, json: bool) -> Result<(u8, Vec<u8>), Error> {
    let s = match &response.response {
        p::ResponseBody::InitializationRequest(s) if &s.origin == q => s,
        p::ResponseBody::Error(e) => return Err(*e),
        _ => return Err(Error::StateUnknown),
    };
    s.validate()?;
    let code = if s.phase == c::Phase::Unknown { 6 } else { 0 };
    let mut bytes = if json {
        p::encode_response(response)?
    } else {
        human(s).into_bytes()
    };
    if json {
        bytes.push(b'\n')
    }
    Ok((code, bytes))
}
fn unconfirmed(q: &c::Query, json: bool) -> (u8, Vec<u8>) {
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({"version":p::VERSION,"ok":false,"origin":q,"admission":"unconfirmed","doNotReplay":true,"message":"Query or stop the same request; do not repeat the change."})).unwrap_or_default()
    } else {
        format!(
            "Acknowledgement unavailable. Do not replay.\n{}",
            receipt(q)
        )
        .into_bytes()
    };
    bytes.push(b'\n');
    (6, bytes)
}
fn execute(parsed: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let (q, body, changes) = match parsed.command {
            Command::Prepare(project, revision) => {
                let info = runtime.block_on(crate::installed_cli_ipc::request(
                    &path,
                    &framed(p::RequestBody::Info(p::Empty {}))?,
                ))?;
                match info.response {
                    p::ResponseBody::Info(_) => {}
                    p::ResponseBody::Error(e) => return Err(e),
                    _ => return Err(Error::StateUnknown),
                }
                let q = c::Query {
                    project_id: project,
                    service_instance: info.service_instance,
                    request_id: Id::random()?,
                };
                (
                    q.clone(),
                    p::RequestBody::InitializationPrepare(c::Prepare {
                        origin: q,
                        expected_observation_revision: revision,
                    }),
                    true,
                )
            }
            Command::Apply(a) => (
                a.origin.clone(),
                p::RequestBody::InitializationApply(a),
                true,
            ),
            Command::Query(q, false) => (q.clone(), p::RequestBody::InitializationStatus(q), false),
            Command::Query(q, true) => (q.clone(), p::RequestBody::InitializationCancel(q), true),
        };
        let request = framed(body)?;
        if changes {
            let mut stderr = std::io::stderr().lock();
            stderr
                .write_all(receipt(&q).as_bytes())
                .and_then(|_| stderr.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = runtime
            .block_on(crate::installed_cli_ipc::request(&path, &request))
            .and_then(|r| output(&r, &q, parsed.json));
        if changes {
            Ok(result.unwrap_or_else(|_| unconfirmed(&q, parsed.json)))
        } else {
            result
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = parsed;
        Err(Error::UnsupportedPlatform)
    }
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|s| s == "--json");
    let (code, bytes) = parse(&args)
        .and_then(execute)
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
    if std::io::stdout().write_all(&bytes).is_err() {
        6
    } else {
        code
    }
}

#[cfg(test)]
#[path = "installed_cli_initialization_tests.rs"]
mod tests;
