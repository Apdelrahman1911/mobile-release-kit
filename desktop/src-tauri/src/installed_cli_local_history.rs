//! Five fixed calls to the already-open Desktop. No provider, candidate,
//! credential, prepared material or release executor exists in this client.
use super::*;
use crate::service_local_history_protocol as store;
use crate::service_local_history_prepare_protocol as prepare;

pub(super) const COMMANDS: [CommandCapability; 5] = [
    CommandCapability {command:"local-history-prepare",arguments:&["PROJECT_ID","SERVICE_INSTANCE","KIND","[UUID [--android|--ios]]"],
        description:"Request read-only native History preparation; separately approve Start in Desktop. No Abandon or Store authority."},
    CommandCapability {
        command: "local-history-scope",
        arguments: &["PROJECT_ID"],
        description:
            "Read an existing Desktop History permission; no automatic Prepare or enrollment.",
    },
    CommandCapability {
        command: "local-history-submit",
        arguments: &[
            "PROJECT_ID",
            "SERVICE_INSTANCE",
            "GRANT_ID",
            "REVIEW_ID",
            "--reviewed",
        ],
        description: "Start the exact Desktop-approved enrollment or local file review once.",
    },
    CommandCapability {
        command: "local-history-status",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description:
            "Read the same retained History request; unknown is never permission to replay.",
    },
    CommandCapability {
        command: "local-history-cancel",
        arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"],
        description: "Stop the original local History request, not delete or repair history.",
    },
];
enum Command {
    Prepare {project:Id,instance:Id,selection:prepare::Selection},
    Scope(Id),
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
        review: Id,
    },
    Status(store::Query),
    Cancel(store::Query),
}
struct Parsed {
    command: Command,
    json: bool,
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    args.first()
        .and_then(|v| v.to_str())
        .is_some_and(|v| COMMANDS.iter().any(|c| c.command == v))
}
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 7 {
        return Err(Error::InvalidRequest);
    }
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
        ["local-history-prepare",project,instance,kind,tail @ ..]=>{
            let kind=match *kind {
                "enroll"=>store::Kind::Enroll,"verify"=>store::Kind::Verify,"review-inputs"=>store::Kind::ReviewInputs,
                "review-prepared"=>store::Kind::ReviewPrepared,"review-execution"=>store::Kind::ReviewExecution,
                "review-reconcile"=>store::Kind::ReviewReconcile,"review-recovery"=>store::Kind::ReviewRecovery,
                "review-stage-prepared"=>store::Kind::ReviewStagePrepared,"review-stage-execution"=>store::Kind::ReviewStageExecution,
                "review-external-readiness"=>store::Kind::ReviewExternalReadiness,_=>return Err(Error::InvalidRequest),
            };
            let (selected,platform)=match tail {
                []=>(None,None),[id]=>(Some((*id).to_owned()),None),
                [id,"--ios"]=>(Some((*id).to_owned()),Some(store::Platform::Ios)),
                [id,"--android"]=>(Some((*id).to_owned()),Some(store::Platform::Android)),_=>return Err(Error::InvalidRequest),
            };
            let selection=prepare::Selection{kind,platform,candidate_operation_id:if kind.stage(){None}else{selected.clone()},
                stage_operation_id:if kind.stage(){selected}else{None}};
            if !selection.valid(){return Err(Error::InvalidRequest);}
            Command::Prepare{project:Id::parse(project)?,instance:Id::parse(instance)?,selection}
        }
        ["local-history-submit", project, instance, grant, review, "--reviewed"] => {
            Command::Submit {
                project: Id::parse(project)?,
                instance: Id::parse(instance)?,
                grant: Id::parse(grant)?,
                review: Id::parse(review)?,
            }
        }
        [kind @ ("local-history-status" | "local-history-cancel"), project, instance, request] => {
            let q = store::Query {
                project_id: Id::parse(project)?,
                service_instance: Id::parse(instance)?,
                request_id: Id::parse(request)?,
            };
            if *kind == "local-history-status" {
                Command::Status(q)
            } else {
                Command::Cancel(q)
            }
        }
        ["local-history-scope", project] => Command::Scope(Id::parse(project)?),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn receipt(q: &store::Query) -> String {
    format!("Request {}\nCheck: mrk local-history-status {} {} {} --json\nStop: mrk local-history-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &store::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"Local History request outcome is not confirmed. Keep this request ID; check its status or cancel. Do not submit again."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "Local History request outcome is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &store::Query,
    submitted: Option<(&Id, &Id)>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    if let p::ResponseBody::LocalHistoryPreparation(status)=&response.response {
        status.validate()?;
        if submitted.is_some()||status.origin!=*q||response.service_instance!=q.service_instance{return Err(Error::StateUnknown);}
        let code=match status.phase {prepare::Phase::Unknown=>6,prepare::Phase::Refused|prepare::Phase::Cancelled|prepare::Phase::Expired=>5,_=>0};
        let bytes=if json {let mut b=p::encode_response(response)?;b.push(b'\n');b}
            else{format!("Local History preparation: {:?}; {:?}.\n{}Comparison only. Use Desktop Check, then separate one-use Start approval. No native execution or enrollment has been authorized.\n",status.phase,status.settlement,receipt(q)).into_bytes()};
        return Ok((code,bytes));
    }
    let p::ResponseBody::LocalHistoryRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted
            .is_some_and(|(grant, review)| &status.grant_id != grant || &status.review_id != review)
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.state {
        store::State::Unknown => 6,
        store::State::Refused
        | store::State::Cancelled
        | store::State::Expired
        | store::State::Failed => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "Local History request: {:?}; {:?}.\n{}",
            status.state,
            status.settlement,
            receipt(q)
        );
        text.push_str("Desktop approved only this enrollment or current local file review. Enrollment creates original local history and Keychain items; it never replaces them. Read results do not establish Store authority or earlier build finality. Keep unknown requests and history intact; do not replay.\n");
        if let Some(result) = &status.result {
            text.push_str(
                &String::from_utf8(
                    serde_json::to_vec_pretty(result).map_err(|_| Error::StateUnknown)?,
                )
                .map_err(|_| Error::StateUnknown)?,
            );
            text.push('\n');
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
            Command::Scope(project) => {
                let path = application_data()?;
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Unavailable)?;
                let request = p::Request {
                    version: p::VERSION,
                    request_id: Id::random()?,
                    request: p::RequestBody::LocalHistoryScope(p::ProjectQuery {
                        project_id: project.clone(),
                    }),
                };
                let response = rt.block_on(crate::installed_cli_ipc::request(&path, &request))?;
                if let p::ResponseBody::Error(e) = response.response {
                    return Err(e);
                }
                let p::ResponseBody::LocalHistoryAccess(a) = &response.response else {
                    return Err(Error::StateUnknown);
                };
                a.validate()?;
                if a.project_id.as_ref().is_some_and(|id| id != &project)
                    || a.service_instance
                        .as_ref()
                        .is_some_and(|id| id != &response.service_instance)
                {
                    return Err(Error::Conflict);
                }
                let bytes = if options.json {
                    let mut b = p::encode_response(&response)?;
                    b.push(b'\n');
                    b
                } else {
                    format!("Local History permission: {}; one-use; {}ms remaining. Prepare and approve the exact action in Desktop first.\n",if a.enabled{"enabled"}else{"not enabled"},a.remaining_ms).into_bytes()
                };
                return Ok((0, bytes));
            }
            Command::Prepare{project,instance,selection}=>{
                let q=store::Query{project_id:project,service_instance:instance,request_id:Id::random()?};
                std::io::stderr().write_all(receipt(&q).as_bytes()).map_err(|_|Error::Unavailable)?;
                (q.clone(),None,p::RequestBody::LocalHistoryPrepare(prepare::Request{origin:q,selection}))
            }
            Command::Submit {
                project,
                instance,
                grant,
                review,
            } => {
                let q = store::Query {
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
                    Some((grant.clone(), review.clone())),
                    p::RequestBody::LocalHistorySubmit(store::Submit {
                        origin: q,
                        grant_id: grant,
                        review_id: review,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, p::RequestBody::LocalHistoryStatus(q)),
            Command::Cancel(q) => (q.clone(), None, p::RequestBody::LocalHistoryCancel(q)),
        };
        let result = (|| {
            let path = application_data()?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Unavailable)?;
            let selected=if let p::RequestBody::LocalHistoryPrepare(v)=&body{Some(v.selection.clone())}else{None};
            let request = p::Request {
                version: p::VERSION,
                request_id: Id::random()?,
                request: body,
            };
            let response = rt.block_on(crate::installed_cli_ipc::request(&path, &request))?;
            if selected.as_ref().is_some_and(|selected|!matches!(&response.response,p::ResponseBody::LocalHistoryPreparation(s) if &s.selection==selected)) {return Err(Error::StateUnknown);}
            output(
                &response,
                &q,
                submitted.as_ref().map(|(a, b)| (a, b)),
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
mod tests {
    use super::*;
    fn id(n: u8) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    fn args(s: &str) -> Vec<OsString> {
        s.split_whitespace().map(OsString::from).collect()
    }
    #[test]
    fn local_history_cli_scalar_codec_closed_and_lost_ack_keeps_same_request() {
        let text = format!(
            "local-history-submit {} {} {} {} --reviewed",
            id(1).as_str(),
            id(2).as_str(),
            id(3).as_str(),
            id(4).as_str()
        );
        for suffix in ["", " --json"] {
            let input = args(&(text.clone() + suffix));
            assert!(recognizes(&input));
            assert!(matches!(
                parse(&input).unwrap().command,
                Command::Submit { .. }
            ));
        }
        for suffix in [" --force", " --reviewed", " --path /inert", " --prepare"] {
            assert!(parse(&args(&(text.clone() + suffix))).is_err());
        }
        assert!(parse(&args(&text.replace(" --reviewed", ""))).is_err());
        assert!(parse(&args(&format!(
            "local-history-scope {} --json",
            id(1).as_str()
        )))
        .is_ok());
        let q = store::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(5),
        };
        for name in ["local-history-status", "local-history-cancel"] {
            assert!(parse(&args(&format!(
                "{name} {} {} {} --json",
                id(1).as_str(),
                id(2).as_str(),
                id(5).as_str()
            )))
            .is_ok());
        }
        let lost: serde_json::Value =
            serde_json::from_slice(&unconfirmed(&q, Error::StateUnknown, true)).unwrap();
        assert_eq!(lost["request"]["requestId"], id(5).as_str());
        assert_eq!(lost["doNotReplay"], true);
        assert!(receipt(&q).contains("local-history-status"));
        let caps = capabilities(true).unwrap();
        assert!(caps.len() <= CAPABILITIES_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&caps).unwrap();
        assert_eq!(value["localHistory"]["savedConfigRequired"], false);
        assert_eq!(value["localHistory"]["cliPrepare"], true);
        assert_eq!(value["localHistory"]["prepareIsStart"], false);
        assert!(value["requestDiscovery"]["families"].as_array().unwrap().iter().any(|v|v=="local-history"));
        assert!(HELP.contains("local-history-submit"));
    }
    #[test]
    fn local_history_cli_status_never_accepts_foreign_family_origin_or_scope() {
        let q = store::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(5),
        };
        let status = store::Status {
            origin: q.clone(),
            grant_id: id(3),
            review_id: id(4),
            revision: 1,
            review: store::Review {
                kind: store::Kind::Verify,
                operation_id: id(10),
                owner_generation: id(11),
                status_revision: 3,
                platform: None,
                candidate_operation_id: None,
                stage_operation_id: None,
            },
            state: store::State::Queued,
            settlement: p::Settlement::Pending,
            reason: store::Reason::None,
            operation: None,
            outcome: None,
            result: None,
        };
        let mut r = p::Response {
            version: p::VERSION,
            service_instance: id(2),
            request_id: id(6),
            client_id: id(8),
            session_id: id(9),
            response: p::ResponseBody::LocalHistoryRequest(Box::new(status)),
        };
        assert_eq!(output(&r, &q, Some((&id(3), &id(4))), false).unwrap().0, 0);
        r.service_instance = id(7);
        assert!(output(&r, &q, None, true).is_err());
        r.service_instance = id(2);
        r.response = p::ResponseBody::LocalHistoryAccess(Box::new(store::Access::empty()));
        assert!(output(&r, &q, None, false).is_err());
    }
    #[test]
    fn local_history_prepare_cli_has_sixteen_closed_contexts_and_no_start_or_origin_fallback(){
        let uuid="12345678-1234-4234-8234-123456789abc";let mut count=0;
        for (kind,suffixes) in [
            ("enroll",vec!["".to_owned()]),("verify",vec!["".to_owned()]),
            ("review-inputs",vec![format!(" {uuid}"),format!(" {uuid} --ios")]),
            ("review-prepared",vec![format!(" {uuid}"),format!(" {uuid} --ios")]),
            ("review-execution",vec![format!(" {uuid}"),format!(" {uuid} --ios")]),
            ("review-reconcile",vec![format!(" {uuid}"),format!(" {uuid} --ios")]),
            ("review-recovery",vec![format!(" {uuid}")]),
            ("review-stage-prepared",vec![format!(" {uuid} --android"),format!(" {uuid} --ios")]),
            ("review-stage-execution",vec![format!(" {uuid} --android"),format!(" {uuid} --ios")]),
            ("review-external-readiness",vec![format!(" {uuid} --ios")])]{
            for suffix in suffixes{let command=format!("local-history-prepare {} {} {kind}{suffix} --json",id(1).as_str(),id(2).as_str());
                let parsed=parse(&args(&command)).unwrap();assert!(parsed.json);let Command::Prepare{project,instance,selection}=parsed.command else{panic!("not Prepare")};
                assert_eq!(project,id(1));assert_eq!(instance,id(2));assert!(selection.valid());count+=1;}
        }assert_eq!(count,16);
        for tail in [format!("abandon-inputs {uuid}"),format!("review-recovery {uuid} --ios"),format!("review-inputs {uuid} --android"),format!("review-stage-prepared {uuid}"),"verify --ios".into(),"verify --reviewed".into(),"verify --root /inert".into()]{assert!(parse(&args(&format!("local-history-prepare {} {} {tail}",id(1).as_str(),id(2).as_str()))).is_err());}
        let q=store::Query{project_id:id(1),service_instance:id(2),request_id:id(5)};
        let status=prepare::Status{origin:q.clone(),selection:prepare::Selection{kind:store::Kind::Verify,platform:None,candidate_operation_id:None,stage_operation_id:None},revision:1,phase:prepare::Phase::Queued,settlement:p::Settlement::Pending,reason:store::Reason::None,review:None,remaining_ms:0};
        let mut response=p::Response{version:p::VERSION,service_instance:id(2),request_id:id(6),client_id:id(8),session_id:id(9),response:p::ResponseBody::LocalHistoryPreparation(Box::new(status))};
        let (code,bytes)=output(&response,&q,None,false).unwrap();assert_eq!(code,0);assert!(String::from_utf8(bytes).unwrap().contains("separate one-use Start"));
        assert!(output(&response,&q,Some((&id(3),&id(4))),false).is_err());
        if let p::ResponseBody::LocalHistoryPreparation(s)=&mut response.response{s.origin.request_id=id(7);}
        assert!(output(&response,&q,None,true).is_err());
    }

}
