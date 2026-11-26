//! Four fixed calls to the already-open Desktop. No provider, candidate,
//! credential, prepared material or release executor exists in this client.
use super::*;
use crate::service_apple_provisioning_protocol as apple;
use crate::service_apple_provisioning_prepare_protocol as prepare;

pub(super) const COMMANDS: [&str; 4] = [
    "apple-provisioning-submit",
    "apple-provisioning-status",
    "apple-provisioning-cancel",
    "apple-provisioning-prepare",
];
enum Command {
    Prepare {project:Id,instance:Id,grant:Id,scope:Id},
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
        review: Id,
    },
    Status(apple::Query),
    Cancel(apple::Query),
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
        ["apple-provisioning-prepare",project,instance,grant,scope,"--reviewed"]=>Command::Prepare {project:Id::parse(project)?,instance:Id::parse(instance)?,grant:Id::parse(grant)?,scope:Id::parse(scope)?},
        ["apple-provisioning-submit", project, instance, grant, review, "--reviewed"] => {
            Command::Submit {
                project: Id::parse(project)?,
                instance: Id::parse(instance)?,
                grant: Id::parse(grant)?,
                review: Id::parse(review)?,
            }
        }
        [kind @ ("apple-provisioning-status" | "apple-provisioning-cancel"), project, instance, request] =>
        {
            let q = apple::Query {
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
fn receipt(q: &apple::Query) -> String {
    format!("Request {}\nCheck: mrk apple-provisioning-status {} {} {} --json\nStop: mrk apple-provisioning-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &apple::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"Apple provisioning request outcome is not confirmed. Keep this request ID; check its status or cancel. Do not submit again."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "Apple provisioning request outcome is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &apple::Query,
    submitted: Option<(&Id, &Id, bool)>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    if let p::ResponseBody::AppleProvisioningPreparation(status)=&response.response {
        status.validate()?;
        if status.origin!=*q||response.service_instance!=q.service_instance||submitted.is_some_and(|(grant,scope,is_prepare)|!is_prepare||&status.grant_id!=grant||&status.scope_id!=scope){return Err(Error::StateUnknown);}
        let code=match status.phase{prepare::Phase::Unknown=>6,prepare::Phase::Refused=>5,_=>0};
        let bytes=if json{let mut b=p::encode_response(response)?;b.push(b'\n');b}else{format!("Apple preparation: {:?}; {:?}.\n{}Preparation only; no provider work, key generation or save has started. Review the exact new intent in Desktop and separately approve Start.\n",status.phase,status.settlement,receipt(q)).into_bytes()};
        return Ok((code,bytes));
    }
    let p::ResponseBody::AppleProvisioningRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted
            .is_some_and(|(grant, review,is_prepare)| is_prepare||&status.grant_id != grant || &status.review_id != review)
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.state {
        apple::State::Unknown => 6,
        apple::State::Refused
        | apple::State::Cancelled
        | apple::State::Expired
        | apple::State::Failed => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "Apple provisioning request: {:?}; {:?}.\n{}",
            status.state,
            status.settlement,
            receipt(q)
        );
        text.push_str("Only the exact Desktop-prepared Apple mode is delegated. Completion is not assignment, signing readiness or permission to repeat a provider request. Return to Desktop for each next review, reconciliation, credential selection or backup.\n");
        if let Some(record) = &status.record_at_completion {
            text.push_str(&format!("A new {:?} record was retained at original completion: {}. Recheck the current vault in Desktop; this historical reference is not assignment.\n",record.kind,record.reference.record_id.as_str()));
        }
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
            Command::Prepare{project,instance,grant,scope}=>{
                let q=apple::Query{project_id:project,service_instance:instance,request_id:Id::random()?};
                std::io::stderr().write_all(receipt(&q).as_bytes()).map_err(|_|Error::Unavailable)?;
                (q.clone(),Some((grant.clone(),scope.clone(),true)),p::RequestBody::AppleProvisioningPrepare(prepare::Submit{origin:q,grant_id:grant,scope_id:scope}))
            },
            Command::Submit {
                project,
                instance,
                grant,
                review,
            } => {
                let q = apple::Query {
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
                    Some((grant.clone(), review.clone(),false)),
                    p::RequestBody::AppleProvisioningSubmit(apple::Submit {
                        origin: q,
                        grant_id: grant,
                        review_id: review,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, p::RequestBody::AppleProvisioningStatus(q)),
            Command::Cancel(q) => (q.clone(), None, p::RequestBody::AppleProvisioningCancel(q)),
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
                submitted.as_ref().map(|(a, b,is_prepare)| (a, b,*is_prepare)),
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
#[path = "installed_cli_apple_provisioning_tests.rs"]
mod tests;
