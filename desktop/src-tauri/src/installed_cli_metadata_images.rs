//! Transport-only prepared image delegation. Scalar IDs, not paths or image
//! payloads. No native editor/runtime/picker module is imported by this client.
use super::*;
use crate::service_metadata_images_protocol as c;
pub(super) const COMMANDS:[CommandCapability;4]=[
    CommandCapability{command:"metadata-images-scope",arguments:&["PROJECT_ID"],description:"Read Desktop's existing image-preview permission; does not choose files or prepare."},
    CommandCapability{command:"metadata-images-submit",arguments:&["PROJECT_ID","SERVICE_INSTANCE","GRANT_ID","--reviewed"],description:"Apply the already Desktop-prepared local image copy once; no Store upload or file arguments."},
    CommandCapability{command:"metadata-images-status",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Read the same retained image request; unknown results never authorize replay."},
    CommandCapability{command:"metadata-images-cancel",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Request the original Stop and retain its outcome; not rollback or recovery authority."},
];
enum Command {
    Scope(Id),
    Submit(c::Submit),
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
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    if args.len() > 6 {
        return Err(Error::InvalidRequest);
    }
    let mut w = args
        .iter()
        .map(|s| {
            s.to_str()
                .filter(|s| s.len() <= 64)
                .ok_or(Error::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let json = w.last() == Some(&"--json");
    if json {
        w.pop();
    }
    let command = match w.as_slice() {
        ["metadata-images-scope", p] => Command::Scope(Id::parse(p)?),
        ["metadata-images-submit", p, i, g, "--reviewed"] => Command::Submit(c::Submit {
            origin: c::Query {
                project_id: Id::parse(p)?,
                service_instance: Id::parse(i)?,
                request_id: Id::random()?,
            },
            grant_id: Id::parse(g)?,
            reviewed: true,
        }),
        ["metadata-images-status", p, i, q] => Command::Query(query(p, i, q)?, false),
        ["metadata-images-cancel", p, i, q] => Command::Query(query(p, i, q)?, true),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed { command, json })
}
fn receipt(q: &c::Query) -> String {
    format!("Request {}\nCheck: mrk metadata-images-status {} {} {} --json\nStop: mrk metadata-images-cancel {} {} {} --json\n",q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str(),q.project_id.as_str(),q.service_instance.as_str(),q.request_id.as_str())
}
pub(super) fn human(s: &c::Status) -> String {
    let mut text = format!(
        "Image copy request: {:?}; {:?}.\n{}",
        s.phase,
        s.settlement,
        receipt(&s.origin)
    );
    text.push_str(&format!(
        "{} images: {} new, {} replace, {} kept.\n",
        s.review.file_count, s.review.create_count, s.review.replace_count, s.review.preserve_count
    ));
    if s.result.as_ref().is_some_and(|r| r.completed) {
        text.push_str(
            "The original local image copy completed. Nothing was uploaded to a Store.\n",
        );
    } else {
        text.push_str("Not a confirmed successful copy. Keep the original request; do not submit it again. Review any recovery requirements in Desktop.\n");
    }
    text
}
fn output(
    r: &p::Response,
    project: &Id,
    origin: Option<&c::Query>,
    grant: Option<&Id>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = r.response {
        return Err(e);
    }
    if grant.is_none() && matches!(&r.response,p::ResponseBody::MetadataImagesPreparation(_)) {
        return super::metadata_images_prepare::output(r,origin.ok_or(Error::StateUnknown)?,json);
    }
    let (code, text) = match (&r.response, origin) {
        (p::ResponseBody::MetadataImagesAccess(a), None) => {
            a.validate()?;
            if a.project_id.as_ref().is_some_and(|p| p != project)
                || a.service_instance != r.service_instance
            {
                return Err(Error::StateUnknown);
            }
            (
                0,
                if a.live {
                    format!("Desktop allows this exact prepared image copy once for {} ms. Review the full preview in Desktop; this is not Store upload permission.\nService {}\nGrant {}\n",a.remaining_ms,a.service_instance.as_str(),a.grant_id.as_ref().ok_or(Error::StateUnknown)?.as_str())
                } else {
                    "No live image-copy permission. Choose and prepare images in Desktop, then explicitly allow that exact preview once.\n".into()
                },
            )
        }
        (p::ResponseBody::MetadataImagesRequest(s), Some(q)) => {
            s.validate()?;
            if &s.origin != q
                || s.origin.service_instance != r.service_instance
                || grant.is_some_and(|g| g != &s.grant_id)
            {
                return Err(Error::StateUnknown);
            }
            (
                if s.phase == c::Phase::Unknown {
                    6
                } else if s.phase == c::Phase::Final
                    && !s.result.as_ref().is_some_and(|f| f.completed)
                {
                    5
                } else {
                    0
                },
                human(s),
            )
        }
        _ => return Err(Error::StateUnknown),
    };
    let bytes = if json {
        let mut b = p::encode_response(r)?;
        b.push(b'\n');
        b
    } else {
        text.into_bytes()
    };
    Ok((code, bytes))
}
fn unconfirmed(q: &c::Query, json: bool) -> (u8, Vec<u8>) {
    let text="Image-copy outcome is not confirmed. Keep this request; check or cancel the original. Do not submit again.";
    let bytes = if json {
        let mut b=serde_json::to_vec(&serde_json::json!({"version":1,"ok":false,"error":"state_unknown","request":q,"doNotReplay":true,"message":text})).unwrap_or_else(|_|b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        b.push(b'\n');
        b
    } else {
        format!("{text}\n{}", receipt(q)).into_bytes()
    };
    (6, bytes)
}
fn execute(parsed: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (project, origin, grant, changes, body) = match parsed.command {
            Command::Scope(id) => (
                id.clone(),
                None,
                None,
                false,
                p::RequestBody::MetadataImagesScope(c::Scope { project_id: id }),
            ),
            Command::Submit(s) => (
                s.origin.project_id.clone(),
                Some(s.origin.clone()),
                Some(s.grant_id.clone()),
                true,
                p::RequestBody::MetadataImagesSubmit(s),
            ),
            Command::Query(q, cancel) => (
                q.project_id.clone(),
                Some(q.clone()),
                None,
                cancel,
                if cancel {
                    p::RequestBody::MetadataImagesCancel(q)
                } else {
                    p::RequestBody::MetadataImagesStatus(q)
                },
            ),
        };
        let request = p::Request {
            version: p::VERSION,
            request_id: Id::random()?,
            request: body,
        };
        p::encode_request(&request)?;
        if changes {
            let q = origin.as_ref().ok_or(Error::StateUnknown)?;
            let mut err = std::io::stderr().lock();
            err.write_all(receipt(q).as_bytes())
                .and_then(|_| err.flush())
                .map_err(|_| Error::StateUnknown)?;
        }
        let result = (|| {
            let path = application_data()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Unavailable)?;
            let r = runtime.block_on(crate::installed_cli_ipc::request(&path, &request))?;
            output(&r, &project, origin.as_ref(), grant.as_ref(), parsed.json)
        })();
        if changes {
            Ok(result.unwrap_or_else(|_| {
                unconfirmed(origin.as_ref().expect("fixed mutating form"), parsed.json)
            }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use c::fixtures::*;
    fn words(a: &[&str]) -> Vec<OsString> {
        a.iter().map(|v| OsString::from(*v)).collect()
    }
    #[test]
    fn image_cli_actual_collector_and_capabilities_admit_only_scalar_prepared_import() {
        let project = id('2');
        let instance = id('1');
        let grant = id('4');
        for command in COMMANDS {
            let mut args = vec![command.command, project.as_str()];
            match command.command {
                "metadata-images-submit" => {
                    args.extend([instance.as_str(), grant.as_str(), "--reviewed"])
                }
                "metadata-images-status" | "metadata-images-cancel" => {
                    args.extend([instance.as_str(), grant.as_str()])
                }
                _ => {}
            }
            args.push("--json");
            let args = super::super::collect_arguments(words(&args));
            assert!(recognizes(&args));
            let parsed = parse(&args).unwrap();
            assert!(parsed.json);
            if let Command::Submit(s) = parsed.command {
                assert_eq!(s.grant_id, grant);
                assert_eq!(s.origin.project_id, project);
                assert_eq!(s.origin.service_instance, instance);
                assert!(s.reviewed);
                assert!(!s.origin.request_id.as_str().is_empty());
            }
        }
        for bad in [
            vec![
                "metadata-images-submit",
                project.as_str(),
                instance.as_str(),
                grant.as_str(),
            ],
            vec![
                "metadata-images-submit",
                project.as_str(),
                instance.as_str(),
                grant.as_str(),
                "--stdin",
            ],
            vec![
                "metadata-images-submit",
                project.as_str(),
                instance.as_str(),
                grant.as_str(),
                "--reviewed",
                "/image.png",
            ],
            vec!["metadata-images-choose", project.as_str()],
            vec!["metadata-images-prepare", project.as_str()],
            vec!["metadata-images-recover", project.as_str()],
            vec![
                "metadata-images-scope",
                project.as_str(),
                "--json",
                "--json",
            ],
            vec![
                "metadata-images-status",
                project.as_str(),
                instance.as_str(),
                "not-an-id",
            ],
        ] {
            assert!(parse(&super::super::collect_arguments(words(&bad))).is_err());
        }
        let bytes = super::super::capabilities(true).unwrap();
        assert!(bytes.len() <= super::super::CAPABILITIES_BYTES);
        let caps: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let images = &caps["metadataImages"];
        assert_eq!(images["commands"].as_array().unwrap().len(), 6);
        assert!(caps["requestDiscovery"]["families"]
            .as_array()
            .unwrap()
            .contains(
                &serde_json::to_value(
                    crate::service_request_catalogue::AdditionalFamily::MetadataImages
                )
                .unwrap()
            ));
        assert_eq!(
            caps["requestDiscovery"]["maxRequests"],
            crate::service_request_catalogue::LIMIT
        );
        for key in [
            "nativeOpenedCliProfileOnly",
            "read",
            "prepare",
            "scalarIdsOnly",
            "oneUseSeparateApproval",
        ] {
            assert_eq!(images[key], true);
        }
        for key in [
            "nativeAvailabilityChecked",
            "chooseFiles",
            "recovery",
            "storeUpload",
            "headless",
        ] {
            assert_eq!(images[key], false);
        }
        let human = String::from_utf8(super::super::capabilities(false).unwrap()).unwrap();
        assert!(
            human.contains("metadata-images-submit")
                && super::super::HELP.contains("metadata-images-submit")
        );
    }
    #[test]
    fn image_cli_same_response_binding_and_lost_ack_never_claim_upload_or_replay() {
        let s = status();
        let q = s.origin.clone();
        let grant = s.grant_id.clone();
        let mut r = p::Response {
            version: p::VERSION,
            request_id: id('6'),
            service_instance: q.service_instance.clone(),
            client_id: id('7'),
            session_id: id('8'),
            response: p::ResponseBody::MetadataImagesRequest(s.clone()),
        };
        assert_eq!(
            output(&r, &q.project_id, Some(&q), Some(&grant), true)
                .unwrap()
                .0,
            0
        );
        let mut foreign = q.clone();
        foreign.request_id = id('9');
        assert!(output(&r, &q.project_id, Some(&foreign), None, true).is_err());
        assert!(output(&r, &q.project_id, Some(&q), Some(&id('f')), true).is_err());
        r.service_instance = id('f');
        assert!(output(&r, &q.project_id, Some(&q), None, true).is_err());
        r.service_instance = q.service_instance.clone();
        let mut u = s.clone();
        u.phase = c::Phase::Unknown;
        u.settlement = p::Settlement::Unknown;
        r.response = p::ResponseBody::MetadataImagesRequest(u);
        let (code, bytes) = output(&r, &q.project_id, Some(&q), None, false).unwrap();
        assert_eq!(code, 6);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("do not submit it again") && !text.contains("completed."));
        let mut d = s;
        d.phase = c::Phase::Final;
        d.settlement = p::Settlement::Settled;
        d.result = Some(done());
        r.response = p::ResponseBody::MetadataImagesRequest(d);
        let text =
            String::from_utf8(output(&r, &q.project_id, Some(&q), None, false).unwrap().1).unwrap();
        assert!(
            text.contains("original local image copy completed")
                && text.contains("Nothing was uploaded")
        );
        let lost = unconfirmed(&q, true);
        assert_eq!(lost.0, 6);
        let v: serde_json::Value = serde_json::from_slice(&lost.1).unwrap();
        assert_eq!(v["request"]["requestId"], q.request_id.as_str());
        assert_eq!(v["doNotReplay"], true);
        assert_eq!(v["error"], "state_unknown");
        r.response = p::ResponseBody::MetadataImagesAccess(access());
        assert!(output(&r, &id('f'), None, None, false).is_err());
    }
}
