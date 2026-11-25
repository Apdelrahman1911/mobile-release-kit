//! Transport-only closed settings commands. Native conversion/owner code must
//! never be imported by the installed mrk executable.
use super::*;
use crate::service_metadata_text_protocol as c;
use std::io::{IsTerminal, Read};
pub(super) const COMMANDS:[CommandCapability;5]=[
    CommandCapability{command:"metadata-text-read",arguments:&["PROJECT_ID","OBSERVATION_REVISION","android|ios","LOCALE"],description:"Load current public metadata for one configured locale through the running Desktop; no source paths."},
    CommandCapability{command:"metadata-text-prepare",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","--stdin"],description:"Preview one complete ordered public-text bundle (252 KiB stdin); no writes or generic JSON merge."},
    CommandCapability{command:"metadata-text-apply",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","SESSION_ID","OWNER_GENERATION","REVISION","PLAN_TOKEN","--reviewed"],description:"Apply once after Desktop's exact native before/after preview permission."},
    CommandCapability{command:"metadata-text-status",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Read the same retained row, including public text only while Loaded; no replay."},
    CommandCapability{command:"metadata-text-cancel",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Stop the original request and wait for native joins; no automatic Load or recovery."},
];
enum Command {
    Read(Id, u64, c::Platform, String),
    Prepare(c::Query),
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
        ["metadata-text-read", p, r, platform, locale] => {
            let n = r.parse::<u64>().map_err(|_| Error::InvalidRequest)?;
            if n == 0 || n.to_string() != *r {
                return Err(Error::InvalidRequest);
            }
            Command::Read(
                Id::parse(p)?,
                n,
                match *platform {
                    "android" => c::Platform::Android,
                    "ios" => c::Platform::Ios,
                    _ => return Err(Error::InvalidRequest),
                },
                {
                    if !c::locale(locale) {
                        return Err(Error::InvalidRequest);
                    }
                    (*locale).into()
                },
            )
        }
        ["metadata-text-status", p, i, q] => Command::Query(query(p, i, q)?, false),
        ["metadata-text-cancel", p, i, q] => Command::Query(query(p, i, q)?, true),
        ["metadata-text-prepare", p, i, q, "--stdin"] => Command::Prepare(query(p, i, q)?),
        ["metadata-text-apply", p, i, q, s, g, r, t, "--reviewed"] => Command::Apply(c::Apply {
            origin: query(p, i, q)?,
            original: original(s, g, r)?,
            plan_token: Id::parse(t)?,
            reviewed: true,
        }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn read_fields(reader: impl Read) -> Result<c::Fields, Error> {
    let mut bytes = Vec::with_capacity(c::STDIN_BYTES + 1);
    reader
        .take((c::STDIN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    c::decode_fields(&bytes)
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
    format!("Inspect without replay: mrk metadata-text-status {} {} {} --json\nRequest STOP: mrk metadata-text-cancel {} {} {} --json\n",q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
pub(super) fn human(s: &c::Status) -> String {
    let phase = serde_json::to_string(&s.phase).unwrap_or_else(|_| "unknown".into());
    let mut out = format!("Metadata text request: {}\n{}", phase, receipt(&s.origin));
    if s.observation.is_some() {
        out.push_str("Public text is available in --json output. Read all fields, preserve absent versus empty, then submit one complete ordered bundle with --stdin.\n");
    }
    if let Some(review) = &s.review {
        out.push_str("The original Desktop editor has the full before/after preview. Apply needs its separate one-use permission.\n");
        if s.permission_live {
            if let Some(o) = &s.original {
                out.push_str(&format!(
                    "mrk metadata-text-apply {} {} {} {} {} {} {} --reviewed --json\n",
                    s.origin.project_id.as_str(),
                    s.origin.service_instance.as_str(),
                    s.origin.request_id.as_str(),
                    o.session_id.as_str(),
                    o.owner_generation.as_str(),
                    o.revision.as_str(),
                    review.plan_token.as_str()
                ));
            }
        }
    }
    if s.result.as_ref().is_some_and(c::Final::saved) {
        out.push_str("The original native save settled; this is not Store publication or release readiness.\n");
    }
    out.push_str("One already-configured locale only. No locale creation, image selection, configuration edit, translation, signing, Store upload or automatic recovery.\n");
    out
}
fn output(response: &p::Response, q: &c::Query, json: bool) -> Result<(u8, Vec<u8>), Error> {
    let s = match &response.response {
        p::ResponseBody::MetadataTextRequest(s) if &s.origin == q => s,
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
            Command::Read(project, revision, platform, locale) => {
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
                    p::RequestBody::MetadataTextRead(c::Read {
                        origin: q,
                        expected_observation_revision: revision,
                        platform,
                        locale,
                    }),
                    true,
                )
            }
            Command::Prepare(q) => {
                if std::io::stdin().is_terminal() {
                    return Err(Error::InvalidRequest);
                }
                let proposal = read_fields(std::io::stdin().lock())?;
                (
                    q.clone(),
                    p::RequestBody::MetadataTextPrepare(c::Prepare {
                        origin: q,
                        proposal,
                    }),
                    true,
                )
            }
            Command::Apply(a) => (a.origin.clone(), p::RequestBody::MetadataTextApply(a), true),
            Command::Query(q, false) => (q.clone(), p::RequestBody::MetadataTextStatus(q), false),
            Command::Query(q, true) => (q.clone(), p::RequestBody::MetadataTextCancel(q), true),
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
#[path = "installed_cli_metadata_text_tests.rs"]
mod tests;
