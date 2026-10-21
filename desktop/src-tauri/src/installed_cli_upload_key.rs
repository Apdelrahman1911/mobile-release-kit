//! Fixed IDs-only delegation to the running Desktop. No key material, paths,
//! native admission, generation or assessment exists in the installed client.
use super::*;
use crate::service_upload_key_protocol as key;
pub(super) const COMMANDS: [&str; 4] = [
    "upload-key-scope",
    "upload-key-submit",
    "upload-key-status",
    "upload-key-cancel",
];
enum Command {
    Scope(Id),
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
    },
    Status(key::Query),
    Cancel(key::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first()
        .and_then(|s| s.to_str())
        .is_some_and(|s| COMMANDS.contains(&s))
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    let mut words = args
        .iter()
        .map(|s| s.to_str().ok_or(Error::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    if words.iter().any(|s| s.len() > 64) {
        return Err(Error::InvalidRequest);
    }
    let json = words.last() == Some(&"--json");
    if json {
        words.pop();
    }
    let command = match words.as_slice() {
        ["upload-key-scope", project] => Command::Scope(Id::parse(project)?),
        ["upload-key-submit", project, instance, grant, "--reviewed"] => Command::Submit {
            project: Id::parse(project)?,
            instance: Id::parse(instance)?,
            grant: Id::parse(grant)?,
        },
        [kind @ ("upload-key-status" | "upload-key-cancel"), project, instance, request] => {
            let q = key::Query {
                project_id: Id::parse(project)?,
                service_instance: Id::parse(instance)?,
                request_id: Id::parse(request)?,
            };
            if *kind == COMMANDS[2] {
                Command::Status(q)
            } else {
                Command::Cancel(q)
            }
        }
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn receipt(q: &key::Query) -> String {
    format!("Request {}\nCheck: mrk upload-key-status {} {} {} --json\nStop: mrk upload-key-cancel {} {} {} --json\n",q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
fn unconfirmed(q: &key::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let mut out=serde_json::to_vec(&serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,"message":"Outcome not confirmed. Keep this request ID and check or stop its original; do not submit again."})).unwrap_or_else(|_|b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        out.push(b'\n');
        out
    } else {
        format!(
            "Outcome not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &key::Query,
    grant: Option<&Id>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::UploadKeyRequest(row) = &response.response else {
        return Err(Error::StateUnknown);
    };
    row.validate()?;
    if row.origin != *q
        || response.service_instance != q.service_instance
        || grant.is_some_and(|g| g != &row.grant_id)
    {
        return Err(Error::StateUnknown);
    }
    let code = match row.state {
        key::State::Unknown | key::State::RecoveryRequired => 6,
        key::State::Refused | key::State::Cancelled | key::State::Failed => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut b = p::encode_response(response)?;
        b.push(b'\n');
        b
    } else {
        let mut out = format!(
            "Upload key: {:?}; {:?}.\n{}",
            row.state,
            row.settlement,
            receipt(q)
        );
        out.push_str(match row.state {
            key::State::SavedUnassigned => {
                "Encrypted key saved, not assigned. Review and assign in Desktop before use.\n"
            }
            key::State::Assigned => {
                "The explicitly reviewed existing key is assigned in this Desktop session.\n"
            }
            _ => "No saved or assigned success is implied by this observation.\n",
        });
        out.push_str(
            "No backup, remember-assignment, recovery acknowledgment or retry was authorized.\n",
        );
        out.into_bytes()
    };
    Ok((code, bytes))
}
fn scope_output(response: &p::Response, project: &Id, json: bool) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::UploadKeyAccess(a) = &response.response else {
        return Err(Error::StateUnknown);
    };
    a.validate()?;
    if a.project_id.as_ref().is_some_and(|p| p != project)
        || a.service_instance
            .as_ref()
            .is_some_and(|i| i != &response.service_instance)
    {
        return Err(Error::StateUnknown);
    }
    if json {
        let mut out = p::encode_response(response)?;
        out.push(b'\n');
        Ok((0, out))
    } else {
        let mut out=String::from("One exact Desktop-reviewed Android upload-key action; CLI read access alone never authorizes it.\n");
        if let (Some(kind), Some(instance), Some(grant)) =
            (a.kind, &a.service_instance, &a.grant_id)
        {
            out.push_str(&format!(
                "Kind: {kind:?}; enabled: {}; consumed: {}.\nInstance: {}\nConsent: {}\n",
                a.enabled,
                a.consumed,
                instance.as_str(),
                grant.as_str()
            ));
        } else {
            out.push_str("No upload-key consent is retained. Prepare or review the existing key in Desktop, then explicitly allow one action.\n");
        }
        out.push_str("Never generate a replacement for an existing/reserved/unknown key. Backup and recovery remain separate Desktop actions.\n");
        Ok((0, out.into_bytes()))
    }
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
        let (origin, grant, project, body) = match options.command {
            Command::Scope(project) => (
                None,
                None,
                Some(project.clone()),
                p::RequestBody::UploadKeyScope(p::ProjectQuery {
                    project_id: project,
                }),
            ),
            Command::Submit {
                project,
                instance,
                grant,
            } => {
                let q = key::Query {
                    project_id: project,
                    service_instance: instance,
                    request_id: Id::random()?,
                };
                // Actual original request ID exists before any connection/send.
                std::io::stderr()
                    .write_all(receipt(&q).as_bytes())
                    .map_err(|_| Error::Unavailable)?;
                (
                    Some(q.clone()),
                    Some(grant.clone()),
                    None,
                    p::RequestBody::UploadKeySubmit(key::Submit {
                        origin: q,
                        grant_id: grant,
                    }),
                )
            }
            Command::Status(q) => (
                Some(q.clone()),
                None,
                None,
                p::RequestBody::UploadKeyStatus(q),
            ),
            Command::Cancel(q) => (
                Some(q.clone()),
                None,
                None,
                p::RequestBody::UploadKeyCancel(q),
            ),
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
            if let Some(q) = &origin {
                output(&response, q, grant.as_ref(), options.json)
            } else {
                scope_output(
                    &response,
                    project.as_ref().ok_or(Error::InvalidRequest)?,
                    options.json,
                )
            }
        })();
        match (result, origin) {
            (Ok(v), _) => Ok(v),
            (Err(e), Some(q)) => Ok((6, unconfirmed(&q, e, options.json))),
            (Err(e), None) => Err(e),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = options;
        Err(Error::UnsupportedPlatform)
    }
}
#[cfg(test)]
#[path = "installed_cli_upload_key_tests.rs"]
mod tests;
