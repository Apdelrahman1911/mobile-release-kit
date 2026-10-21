//! Transport-only closed settings commands. Native conversion/owner code must
//! never be imported by the installed mrk executable.
use super::*;
use crate::service_configuration_protocol as c;
use std::io::{IsTerminal, Read};
pub(super) const COMMANDS:[CommandCapability;5]=[
    CommandCapability{command:"configuration-read",arguments:&["PROJECT_ID","OBSERVATION_REVISION"],description:"Read safe settings through Desktop's original Config editor; requires live READ and idle peers."},
    CommandCapability{command:"configuration-prepare",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","SESSION_ID","OWNER_GENERATION","REVISION","--stdin"],description:"Preview one closed settings change; no write or arbitrary JSON merge."},
    CommandCapability{command:"configuration-apply",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","SESSION_ID","OWNER_GENERATION","REVISION","PLAN_TOKEN","--reviewed"],description:"Apply once after exact Desktop preview permission; no replay after a missing ACK."},
    CommandCapability{command:"configuration-status",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Inspect this retained original; not a retry."},
    CommandCapability{command:"configuration-cancel",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Request original STOP; still wait for actual native cleanup."},
];
enum Command {
    Read(Id, u64),
    Prepare(c::Query, c::Original),
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
        ["configuration-read", p, r] => {
            let n = r.parse::<u64>().map_err(|_| Error::InvalidRequest)?;
            if n == 0 || n.to_string() != *r {
                return Err(Error::InvalidRequest);
            }
            Command::Read(Id::parse(p)?, n)
        }
        ["configuration-status", p, i, q] => Command::Query(query(p, i, q)?, false),
        ["configuration-cancel", p, i, q] => Command::Query(query(p, i, q)?, true),
        ["configuration-prepare", p, i, q, s, g, r, "--stdin"] => {
            Command::Prepare(query(p, i, q)?, original(s, g, r)?)
        }
        ["configuration-apply", p, i, q, s, g, r, t, "--reviewed"] => Command::Apply(c::Apply {
            origin: query(p, i, q)?,
            original: original(s, g, r)?,
            plan_token: Id::parse(t)?,
            reviewed: true,
        }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn read_change(reader: impl Read) -> Result<c::Change, Error> {
    let mut bytes = Vec::new();
    reader
        .take((c::CHANGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    if bytes.is_empty() || bytes.len() > c::CHANGE_BYTES {
        return Err(Error::InvalidRequest);
    }
    let change: c::Change = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    change.validate()?;
    Ok(change)
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
    format!("Inspect without replay: mrk configuration-status {} {} {} --json\nRequest STOP: mrk configuration-cancel {} {} {} --json\n",q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
pub(super) fn human(s: &c::Status) -> String {
    let mut out = format!("{}Configuration: {:?}\n", receipt(&s.origin), s.phase);
    if let Some(o) = &s.original {
        out.push_str(&format!(
            "Original {} / {} / {}\n",
            o.session_id.as_str(),
            o.owner_generation.as_str(),
            o.revision.as_str()
        ));
    }
    if let Some(settings) = &s.settings {
        if let Ok(value) = serde_json::to_string_pretty(settings) {
            out.push_str(&value);
            out.push('\n')
        }
    }
    if let Some(r) = &s.review {
        out.push_str("Exact safe-settings comparison (all other fields preserved):\n");
        if let Ok(value) = serde_json::to_string_pretty(
            &serde_json::json!({"before":r.before,"after":r.after,"files":r.files,"ignoreAdditions":r.ignore_additions,"rewritesConfigFormatting":r.rewrites_config_formatting,"createReleaseDirectory":r.create_release_directory}),
        ) {
            out.push_str(&value);
            out.push('\n')
        }
        out.push_str("Desktop must allow this exact preview once; unsaved Desktop drafts are never replaced.\n");
        if s.permission_live {
            if let Some(o) = &s.original {
                out.push_str(&format!(
                    "mrk configuration-apply {} {} {} {} {} {} {} --reviewed --json\n",
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
        out.push_str("Original native save settled. A newer or dirty Desktop draft is preserved as a conflict.\n")
    }
    out.push_str("No identity, version, enabled-platform, command, signing, credential, recovery or release-readiness changes are authorized here.\n");
    out
}
fn output(response: &p::Response, q: &c::Query, json: bool) -> Result<(u8, Vec<u8>), Error> {
    let s = match &response.response {
        p::ResponseBody::ConfigurationRequest(s) if &s.origin == q => s,
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
            Command::Read(project, revision) => {
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
                    p::RequestBody::ConfigurationRead(c::Read {
                        origin: q,
                        expected_observation_revision: revision,
                    }),
                    true,
                )
            }
            Command::Prepare(q, original) => {
                if std::io::stdin().is_terminal() {
                    return Err(Error::InvalidRequest);
                }
                let change = read_change(std::io::stdin().lock())?;
                (
                    q.clone(),
                    p::RequestBody::ConfigurationPrepare(c::Prepare {
                        origin: q,
                        original,
                        change,
                    }),
                    true,
                )
            }
            Command::Apply(a) => (
                a.origin.clone(),
                p::RequestBody::ConfigurationApply(a),
                true,
            ),
            Command::Query(q, false) => (q.clone(), p::RequestBody::ConfigurationStatus(q), false),
            Command::Query(q, true) => (q.clone(), p::RequestBody::ConfigurationCancel(q), true),
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
#[path = "installed_cli_configuration_tests.rs"]
mod tests;
