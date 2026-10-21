//! Combined preparation and separately approved Save in the running Desktop.
//! No source path, counter, credential or second Edit executor.
use super::*;
use crate::service_version_edit_protocol as edit;
use crate::service_version_edit_prepare_protocol as prepare;

pub(super) const COMMANDS: [&str; 4] = [
    "version-edit-submit",
    "version-edit-status",
    "version-edit-cancel",
    "version-edit-prepare",
];
enum Command {
    Prepare { project:Id, instance:Id, selection:prepare::Selection },
    Submit {
        project: Id,
        instance: Id,
        grant: Id,
        session: Id,
        plan: Id,
    },
    Status(edit::Query),
    Cancel(edit::Query),
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
        ["version-edit-prepare",project,instance,"--manual",name,build]=>{
            let values=prepare::Values{name:(*name).into(),build:(*build).into()};if !values.valid(){return Err(Error::InvalidRequest)}
            Command::Prepare{project:Id::parse(project)?,instance:Id::parse(instance)?,selection:prepare::Selection::Manual{values}}
        },
        ["version-edit-prepare",project,instance,"--reserved",reservation]=>Command::Prepare{project:Id::parse(project)?,instance:Id::parse(instance)?,selection:prepare::Selection::Reserved{reservation_id:Id::parse(reservation)?}},
        ["version-edit-submit", project, instance, grant, session, plan, "--reviewed"] => {
            Command::Submit {
                project: Id::parse(project)?,
                instance: Id::parse(instance)?,
                grant: Id::parse(grant)?,
                session: Id::parse(session)?,
                plan: Id::parse(plan)?,
            }
        }
        [kind @ ("version-edit-status" | "version-edit-cancel"), project, instance, request] => {
            let q = edit::Query {
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
fn receipt(q: &edit::Query) -> String {
    format!("Request {}\nCheck: mrk version-edit-status {} {} {} --json\nStop: mrk version-edit-cancel {} {} {} --json\n",
        q.request_id.as_str(), q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str(),
        q.project_id.as_str(), q.service_instance.as_str(), q.request_id.as_str())
}
fn unconfirmed(q: &edit::Query, error: Error, json: bool) -> Vec<u8> {
    if json {
        let value = serde_json::json!({"version":1,"ok":false,"error":error,"request":q,"doNotReplay":true,
            "message":"Version edit outcome is not confirmed. Keep this request ID; check its status or cancel. Do not submit again."});
        let mut bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n');
        bytes
    } else {
        format!(
            "Version edit outcome is not confirmed. Do not submit again.\n{}",
            receipt(q)
        )
        .into_bytes()
    }
}
fn output(
    response: &p::Response,
    q: &edit::Query,
    submitted: Option<(&Id, &Id, &Id)>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    if let p::ResponseBody::VersionEditPreparation(status)=&response.response{
        if submitted.is_some()||status.origin!=*q||response.service_instance!=q.service_instance{return Err(Error::StateUnknown)}
        status.validate()?;
        let code=match status.phase{prepare::Phase::Unknown=>6,prepare::Phase::Stopping=>5,_=>0};
        let bytes=if json{let mut b=p::encode_response(response)?;b.push(b'\n');b}else{
            let mut s=format!("Version preparation: {:?}; {:?}.\n{}",status.phase,status.settlement,receipt(q));
            if let Some(c)=&status.checkout{s.push_str(&format!("Current {} (build {}); {}.\n",c.values.name,c.values.build,c.source));}
            if let Some(r)=&status.review{s.push_str(&format!("Prepared {} (build {}); before {} / after {}.\n",r.name,r.build,r.before_sha256,r.after_sha256));}
            s.push_str("Review this original preview in Desktop, then allow this exact Save once. Preparation does not save, commit, enroll, allocate, or upload.\n");s.into_bytes()};
        return Ok((code,bytes));
    }
    let p::ResponseBody::VersionEditRequest(status) = &response.response else {
        return Err(Error::StateUnknown);
    };
    status.validate()?;
    if status.origin != *q
        || response.service_instance != q.service_instance
        || submitted.is_some_and(|(grant, session, plan)| {
            &status.grant_id != grant
                || &status.review.original.session_id != session
                || &status.review.original.plan_token != plan
        })
    {
        return Err(Error::StateUnknown);
    }
    let code = match status.phase {
        edit::Phase::Unknown => 6,
        edit::Phase::Stopping => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut bytes = p::encode_response(response)?;
        bytes.push(b'\n');
        bytes
    } else {
        let mut text = format!(
            "Version edit: {:?}; {:?}.\n{}",
            status.phase,
            status.settlement,
            receipt(q)
        );
        text.push_str(&format!(
            "Prepared {} (build {}); {}.\n",
            status.review.name, status.review.build, status.review.source
        ));
        if let Some(result) = &status.result {
            text.push_str(&format!(
                "Effect: {:?}; journal: {:?}; cancelled: {}.\n",
                result.effect, result.journal, result.cancelled
            ));
        }
        text.push_str("The original Desktop preview and one-use approval are required. This does not commit, upload, enroll, or allocate a version.\n");
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
        let (q, submitted, preparing, body) = match options.command {
            Command::Prepare{project,instance,selection}=>{
                let q=edit::Query{project_id:project,service_instance:instance,request_id:Id::random()?};
                std::io::stderr().write_all(receipt(&q).as_bytes()).map_err(|_|Error::Unavailable)?;
                (q.clone(),None,Some(selection.clone()),p::RequestBody::VersionEditPrepare(prepare::Prepare{origin:q,selection}))
            },
            Command::Submit {
                project,
                instance,
                grant,
                session,
                plan,
            } => {
                let q = edit::Query {
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
                    Some((grant.clone(), session.clone(), plan.clone())),
                    None,
                    p::RequestBody::VersionEditSubmit(edit::Submit {
                        origin: q,
                        grant_id: grant,
                        session_id: session,
                        plan_token: plan,
                        reviewed: true,
                    }),
                )
            }
            Command::Status(q) => (q.clone(), None, None, p::RequestBody::VersionEditStatus(q)),
            Command::Cancel(q) => (q.clone(), None, None, p::RequestBody::VersionEditCancel(q)),
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
            if let Some(expected)=&preparing{
                if !matches!(&response.response,p::ResponseBody::VersionEditPreparation(s) if &s.selection==expected){return Err(Error::StateUnknown)}
            }
            output(
                &response,
                &q,
                submitted.as_ref().map(|(a, b, c)| (a, b, c)),
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
    fn id(n: char) -> Id {
        Id::parse(&n.to_string().repeat(32)).unwrap()
    }
    fn words(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }
    #[test]
    fn actual_collector_preserves_three_id_only_verbs_and_explicit_review() {
        let i = "11111111111111111111111111111111";
        let args = super::super::collect_arguments(words(&[
            COMMANDS[0],
            i,
            i,
            i,
            i,
            i,
            "--reviewed",
            "--json",
        ]));
        let result = parse(&args).unwrap();
        assert!(result.json);
        assert!(matches!(result.command, Command::Submit { .. }));
        for kind in &COMMANDS[1..3] {
            assert!(parse(&words(&[kind, i, i, i])).is_ok());
        }
        for bad in [
            words(&[COMMANDS[0], i, i, i, i, i]),
            words(&[COMMANDS[0], i, i, i, i, i, "--reviewed", "--path", "file"]),
            words(&["version-edit-prepare", i]),
            words(&[COMMANDS[1], i, i, i, "--retry"]),
        ] {
            assert!(parse(&super::super::collect_arguments(bad)).is_err());
        }
    }
    fn status() -> edit::Status {
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"origin":{"projectId":id('1'),"serviceInstance":id('2'),"requestId":id('3')},"grantId":id('4'),"revision":1,"phase":"queued","settlement":"pending",
            "review":{"original":{"sessionId":id('5'),"ownerGeneration":id('6'),"revision":id('7'),"planToken":id('8')},"nativeStatusRevision":1,"name":"1.2","build":"8","source":"public/version.properties","beforeBytes":20,"beforeSha256":"a".repeat(64),"afterBytes":20,"afterSha256":"b".repeat(64),"candidateId":null},"cancelRequested":false,"result":null,"doNotReplay":true})).unwrap()
    }
    #[test]
    fn output_matches_same_original_and_unknown_never_claims_new_save_permission() {
        let s = status();
        let q = s.origin.clone();
        let mut response = p::Response {
            version: p::VERSION,
            request_id: id('9'),
            service_instance: q.service_instance.clone(),
            client_id: id('a'),
            session_id: id('b'),
            response: p::ResponseBody::VersionEditRequest(s.clone()),
        };
        let expected = Some((
            &s.grant_id,
            &s.review.original.session_id,
            &s.review.original.plan_token,
        ));
        assert_eq!(output(&response, &q, expected, true).unwrap().0, 0);
        let mut foreign = q.clone();
        foreign.request_id = id('c');
        assert!(output(&response, &foreign, expected, true).is_err());
        assert!(output(
            &response,
            &q,
            Some((
                &id('d'),
                &s.review.original.session_id,
                &s.review.original.plan_token
            )),
            true
        )
        .is_err());
        let mut unknown = s;
        unknown.phase = edit::Phase::Unknown;
        unknown.settlement = p::Settlement::Unknown;
        response.response = p::ResponseBody::VersionEditRequest(unknown);
        let (code, bytes) = output(&response, &q, None, false).unwrap();
        assert_eq!(code, 6);
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("Desktop preview"));
        let missing = String::from_utf8(unconfirmed(&q, Error::StateUnknown, true)).unwrap();
        assert!(
            missing.contains(q.request_id.as_str())
                && missing.contains("doNotReplay")
                && !missing.contains("--retry")
        );
    }
    #[test]
    fn compiled_capabilities_disclose_prepared_only_scope_and_same_catalogue() {
        let value: serde_json::Value =
            serde_json::from_slice(&super::super::capabilities(true).unwrap()).unwrap();
        let edit = &value["versionEdit"];
        assert_eq!(edit["cliOpenPrepare"], true);
        assert_eq!(edit["readGrantAuthorizesEdits"], false);
        assert_eq!(edit["reservedHandoffReconstructed"], false);
        assert_eq!(edit["nativeAvailabilityChecked"], false);
        assert_eq!(edit["commands"].as_array().unwrap().len(), 4);
        let text = String::from_utf8(super::super::capabilities(false).unwrap()).unwrap();
        assert!(text.contains("version-edit-submit"));
        assert!(text.contains("version-edit-prepare"));
    }

    #[test]
    fn actual_collector_accepts_only_manual_values_or_original_reservation() {
        let i = "11111111111111111111111111111111";
        for (tail, reserved) in [
            (vec!["--manual", "1.2", "10000"], false),
            (vec!["--reserved", i], true),
        ] {
            let mut args = vec!["version-edit-prepare", i, i];
            args.extend(tail);
            args.push("--json");
            let args = super::super::collect_arguments(words(&args));
            assert!(recognizes(&args));
            let parsed = parse(&args).unwrap();
            assert!(parsed.json);
            let Command::Prepare { project, instance, selection } = parsed.command else { panic!("fixed prepare") };
            assert_eq!(project.as_str(), i);
            assert_eq!(instance.as_str(), i);
            assert_eq!(matches!(selection, prepare::Selection::Reserved { .. }), reserved);
        }
        for tail in [
            vec!["--manual", "1.2", "8", "--reserved", i],
            vec!["--manual", "1.2", "-1"],
            vec!["--manual", "1.2\n", "8"],
            vec!["--manual", "1.2", "12345678901"],
            vec!["--reserved", "candidate-not-an-original-id"],
            vec!["--reserved", i, "--reviewed"],
            vec!["--path", "public/version.properties"],
            vec!["--increment", "patch"],
        ] {
            let mut args = vec!["version-edit-prepare", i, i];
            args.extend(tail);
            assert!(parse(&super::super::collect_arguments(words(&args))).is_err());
        }
    }

    #[test]
    fn preparation_output_is_exact_kind_original_and_never_an_apply_receipt() {
        let q = status().origin;
        let s: prepare::Status = serde_json::from_value(serde_json::json!({
            "schemaVersion":1,"origin":q,"runtimeProjectId":"native-project",
            "selection":{"kind":"manual","values":{"name":"1.2","build":"8"}},
            "revision":1,"phase":"queued","settlement":"pending","original":null,
            "checkout":null,"proposed":null,"review":null,"applyRequest":null,
            "guiOwned":false,"cancelRequested":false,"result":null,"doNotReplay":true
        })).unwrap();
        let mut response = p::Response {
            version:p::VERSION,request_id:id('9'),service_instance:q.service_instance.clone(),
            client_id:id('a'),session_id:id('b'),response:p::ResponseBody::VersionEditPreparation(s.clone()),
        };
        assert!(output(&response, &q, None, true).is_ok());
        let text=String::from_utf8(output(&response,&q,None,false).unwrap().1).unwrap();
        assert!(text.contains("does not save") && text.contains("allow this exact Save once"));
        let mut foreign=q.clone();foreign.request_id=id('d');
        assert!(output(&response,&foreign,None,true).is_err());
        assert!(output(&response,&q,Some((&id('4'),&id('5'),&id('8'))),true).is_err());
        let mut lost=s;lost.phase=prepare::Phase::Unknown;lost.settlement=p::Settlement::Unknown;
        response.response=p::ResponseBody::VersionEditPreparation(lost);
        assert_eq!(output(&response,&q,None,true).unwrap().0,6);
    }
}
