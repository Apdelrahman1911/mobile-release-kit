//! Fixed Prepare/Start/status/STOP transport for the same Desktop proposal.
//! No headless engine, arbitrary edit, implicit retry or new operation ID.
use super::*;
use crate::agent_identity_requests::{actions as action, Query};
enum Command {
    Prepare(Query),
    Start(action::Start),
    Query(Query, bool),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first().is_some_and(|a| {
        [
            "identity-prepare",
            "identity-start",
            "identity-status",
            "identity-cancel",
        ]
        .iter()
        .any(|s| a == *s)
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
    let query = |p: &str, i: &str, q: &str| -> Result<Query, Error> {
        Ok(Query {
            project_id: Id::parse(p)?,
            service_instance: Id::parse(i)?,
            intent_id: Id::parse(q)?,
        })
    };
    let command = match words.as_slice() {
        ["identity-prepare", p, i, q] => Command::Prepare(query(p, i, q)?),
        ["identity-status", p, i, q] => Command::Query(query(p, i, q)?, false),
        ["identity-cancel", p, i, q] => Command::Query(query(p, i, q)?, true),
        ["identity-start", p, i, q, sid, generation, revision, plan, "--reviewed"] => {
            Command::Start(action::Start {
                origin: query(p, i, q)?,
                original: action::Original {
                    operation_id: Id::parse(sid)?,
                    owner_generation: Id::parse(generation)?,
                    revision: Id::parse(revision)?,
                },
                plan_token: Id::parse(plan)?,
                reviewed: true,
            })
        }
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
fn receipt(q: &Query) -> String {
    format!("Inspect without replay: mrk identity-status {} {} {} --json\nRequest STOP: mrk identity-cancel {} {} {} --json\n",
        q.project_id.as_str(), q.service_instance.as_str(), q.intent_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.intent_id.as_str())
}
pub(super) fn human(s: &action::Status) -> String {
    let mut out = format!(
        "{}Original session {} / {}\nPrepare: {:?} · Start: {:?}\nExact requested ID: {}\n",
        receipt(&s.origin),
        s.original.operation_id.as_str(),
        s.original.owner_generation.as_str(),
        s.prepare,
        s.start,
        s.change.desired_identity
    );
    if let Some(o) = &s.observation {
        out.push_str(&format!(
            "Original operation: {:?} · {:?}\n",
            o.state, o.settlement
        ));
        if let Some(r) = &o.review {
            out.push_str(&format!("{} → {}\n", r.before_identity, r.after_identity));
            for row in &r.changes {
                out.push_str(&format!("{}:{}:{}\n", row.path, row.line, row.column));
            }
            if r.new_application_warning {
                out.push_str("This is a different app, not an update to an existing app. Store availability has not been checked.\n");
            }
            if s.permission_live
                && !s.cancel_requested
                && !s.unconfirmed
                && s.start == action::Step::NotRequested
                && o.state == p::OperationState::Prepared
                && o.settlement == p::Settlement::Pending
            {
                out.push_str(&format!("After reviewing this exact preview, start once:\nmrk identity-start {} {} {} {} {} {} {} --reviewed --json\n",
                    s.origin.project_id.as_str(), s.origin.service_instance.as_str(), s.origin.intent_id.as_str(), s.original.operation_id.as_str(),
                    s.original.owner_generation.as_str(), s.original.revision.as_str(), r.plan_token.as_str()));
            }
        }
    }
    if s.unconfirmed {
        out.push_str(
            "Admission could not be confirmed. Do not replay or create a replacement request.\n",
        );
    }
    out.push_str("Namespaces/source packages and version reservations are preserved. Validate the built app before release. Recovery, if needed, stays in the original Desktop editor. Shared history is separate; a missing row does not settle this operation.\n");
    out
}
fn unconfirmed(q: &Query, error: Error, json: bool) -> Vec<u8> {
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({"version":p::VERSION,"ok":false,"error":error,"origin":q,
        "admission":"unconfirmed","doNotReplay":true,"message":"Acknowledgement unavailable. Query or cancel this exact original request; do not repeat the edit."})).unwrap_or_default()
    } else {
        format!(
            "Acknowledgement unavailable. Do not replay.\n{}{}\n",
            receipt(q),
            error.message()
        )
        .into_bytes()
    };
    bytes.push(b'\n');
    bytes
}
fn output(response: &p::Response, q: &Query, json: bool) -> Result<(u8, Vec<u8>), Error> {
    let status = match &response.response {
        p::ResponseBody::IdentityAction(s) if &s.origin == q => s,
        p::ResponseBody::Error(e) => return Err(*e),
        _ => return Err(Error::StateUnknown),
    };
    status.validate()?;
    let code = if status.unconfirmed
        || status
            .observation
            .as_ref()
            .is_some_and(|o| o.settlement == p::Settlement::Unknown)
    {
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
    let json = args.iter().any(|a| a == "--json");
    let result = parse(&args)
        .and_then(execute)
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
    if std::io::stdout().write_all(&result.1).is_err() {
        6
    } else {
        result.0
    }
}
fn execute(parsed: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (query, body, mutating) = match parsed.command {
            Command::Prepare(q) => (q.clone(), p::RequestBody::IdentityPrepare(q), true),
            Command::Start(s) => (s.origin.clone(), p::RequestBody::IdentityStart(s), true),
            Command::Query(q, false) => (q.clone(), p::RequestBody::IdentityActionStatus(q), false),
            Command::Query(q, true) => (q.clone(), p::RequestBody::IdentityCancel(q), true),
        };
        let request = framed(body)?;
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        if mutating {
            let mut stderr = std::io::stderr().lock();
            stderr
                .write_all(receipt(&query).as_bytes())
                .and_then(|_| stderr.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = runtime
            .block_on(crate::installed_cli_ipc::request(&path, &request))
            .and_then(|r| output(&r, &query, parsed.json));
        if mutating {
            Ok(result.unwrap_or_else(|e| (6, unconfirmed(&query, e, parsed.json))))
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
#[cfg(test)]
mod tests {
    use super::*;
    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }
    #[test]
    fn original_cli_collection_preserves_start_and_rejects_trailing_arguments() {
        let id = "a".repeat(32);
        let mut words = args(&[
            "identity-start",
            &id,
            &id,
            &id,
            &id,
            &id,
            &id,
            &id,
            "--reviewed",
        ]);
        for json in [false, true] {
            if json {
                words.push(OsString::from("--json"));
            }
            // This is the SAME bounded collector used by installed_cli::run,
            // followed by its actual child parser; no IPC or native call.
            let captured = super::super::collect_arguments(words.clone());
            assert_eq!(captured.len(), if json { 10 } else { 9 });
            assert!(recognizes(&captured));
            let parsed = parse(&captured).unwrap_or_else(|_| panic!("fixed exact Start"));
            assert!(matches!(parsed.command, Command::Start(_)));
            assert_eq!(parsed.json, json);
        }
        // Even an unbounded iterator is sampled finitely, with a preserved
        // extra word making an otherwise-valid ten-word prefix refuse.
        let oversized = super::super::collect_arguments(
            words
                .into_iter()
                .chain(std::iter::repeat(OsString::from("unexpected"))),
        );
        assert_eq!(oversized.len(), 11);
        assert!(parse(&oversized).is_err());
    }
    #[test]
    fn exact_cli_args_require_reviewed_plan_not_new_identity_or_command() {
        let id = "a".repeat(32);
        assert!(parse(&args(&["identity-prepare", &id, &id, &id, "--json"])).is_ok());
        assert!(parse(&args(&[
            "identity-start",
            &id,
            &id,
            &id,
            &id,
            &id,
            &id,
            &id,
            "--reviewed",
            "--json"
        ]))
        .is_ok());
        for tail in [
            "--apply",
            "--command",
            "--root",
            "com.example.new",
            "--stdin",
        ] {
            assert!(parse(&args(&["identity-prepare", &id, &id, &id, tail])).is_err());
        }
        assert!(parse(&args(&[
            "identity-start",
            &id,
            &id,
            &id,
            &id,
            &id,
            &id,
            &id
        ]))
        .is_err());
    }
    #[test]
    fn lost_ack_keeps_same_intent_and_has_no_retry_or_assumed_finality() {
        let q = Query {
            service_instance: Id::parse(&"a".repeat(32)).unwrap(),
            project_id: Id::parse(&"b".repeat(32)).unwrap(),
            intent_id: Id::parse(&"c".repeat(32)).unwrap(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
        assert_eq!(value["origin"], serde_json::to_value(&q).unwrap());
        assert_eq!(value["doNotReplay"], true);
        assert!(!value.as_object().unwrap().contains_key("settlement"));
        assert!(receipt(&q).contains("identity-cancel"));
    }
}
