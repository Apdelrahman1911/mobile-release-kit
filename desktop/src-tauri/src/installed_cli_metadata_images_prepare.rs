//! Fixed READ/Prepare client. Images, paths, pickers and native modules stay
//! in the already running Desktop; this never reconstructs a captured source.
use super::*;
use crate::service_metadata_images_prepare_protocol as c;
use std::io::{IsTerminal, Read};
pub(super) const COMMANDS:[CommandCapability;2]=[
 CommandCapability{command:"metadata-images-read",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Inspect IDs of the untouched native-opened CLI-profile image selection. No file paths or picker."},
 CommandCapability{command:"metadata-images-prepare",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","--stdin"],description:"Prepare exact observed item IDs/replacement choices (4KiB stdin). Separate Desktop preview and Apply approval remain required."},
];
struct Parsed {
    origin: c::Query,
    prepare: bool,
    json: bool,
}
pub(super) fn recognizes(a: &[OsString]) -> bool {
    a.first()
        .is_some_and(|v| COMMANDS.iter().any(|c| v == c.command))
}
fn parse(a: &[OsString]) -> Result<Parsed, Error> {
    if a.len() > 6 {
        return Err(Error::InvalidRequest);
    }
    let mut v = a
        .iter()
        .map(|s| {
            s.to_str()
                .filter(|s| s.len() <= 64)
                .ok_or(Error::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let json = v.last() == Some(&"--json");
    if json {
        v.pop();
    }
    let (p, i, q, prepare) = match v.as_slice() {
        ["metadata-images-read", p, i, q] => (*p, *i, *q, false),
        ["metadata-images-prepare", p, i, q, "--stdin"] => (*p, *i, *q, true),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed {
        origin: c::Query {
            project_id: Id::parse(p)?,
            service_instance: Id::parse(i)?,
            request_id: Id::parse(q)?,
        },
        prepare,
        json,
    })
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fields {
    observation_revision: u32,
    opened_sha256: String,
    choices: Vec<c::Choice>,
}
fn fields(mut reader: impl Read, q: c::Query) -> Result<c::Prepare, Error> {
    let mut b = Vec::with_capacity(c::REQUEST_BYTES + 1);
    reader
        .by_ref()
        .take((c::REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|_| Error::InvalidRequest)?;
    let v = crate::service_metadata_text_protocol::strict_small_request(&b)?;
    let f: Fields = serde_json::from_value(v).map_err(|_| Error::InvalidRequest)?;
    let input = c::Prepare {
        origin: q,
        observation_revision: f.observation_revision,
        opened_sha256: f.opened_sha256,
        choices: f.choices,
    };
    input.validate()?;
    Ok(input)
}
pub(super) fn human(s: &c::Status) -> String {
    let mut out = format!(
        "Image preparation: {:?}; {:?}.\nRequest {}\n",
        s.phase,
        s.settlement,
        s.origin.request_id.as_str()
    );
    if s.observation.is_some() {
        out.push_str("Use --json for original item IDs and complete replacement choices; no source paths/bytes are exposed.\n");
    }
    if s.review.is_some() {
        out.push_str("The existing Desktop preview is prepared, not applied. Review it and explicitly allow the separate Apply.\n");
    }
    out.push_str("Desktop Choose/Open with the CLI-preparation option is required; untouched Import only. Recovery, choosing files and Store upload stay outside this command. Unknown never permits replay.\n");
    out
}
pub(super) fn output(r: &p::Response, q: &c::Query, json: bool) -> Result<(u8, Vec<u8>), Error> {
    let s = match &r.response {
        p::ResponseBody::MetadataImagesPreparation(s)
            if &s.origin == q && q.service_instance == r.service_instance =>
        {
            s
        }
        p::ResponseBody::Error(e) => return Err(*e),
        _ => return Err(Error::StateUnknown),
    };
    s.validate()?;
    let code = if s.settlement == p::Settlement::Unknown {
        6
    } else {
        0
    };
    let mut b = if json {
        p::encode_response(r)?
    } else {
        human(s).into_bytes()
    };
    if json {
        b.push(b'\n')
    }
    Ok((code, b))
}
fn execute(a: Parsed) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let body = if a.prepare {
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                return Err(Error::InvalidRequest);
            }
            p::RequestBody::MetadataImagesPrepare(fields(stdin.lock(), a.origin.clone())?)
        } else {
            p::RequestBody::MetadataImagesRead(c::Read {
                origin: a.origin.clone(),
            })
        };
        let request = p::Request {
            version: p::VERSION,
            request_id: Id::random()?,
            request: body,
        };
        p::encode_request(&request)?;
        let receipt = format!(
            "Keep request {}. Check: mrk metadata-images-status {} {} {} --json\n",
            a.origin.request_id.as_str(),
            a.origin.project_id.as_str(),
            a.origin.service_instance.as_str(),
            a.origin.request_id.as_str()
        );
        std::io::stderr()
            .write_all(receipt.as_bytes())
            .map_err(|_| Error::StateUnknown)?;
        let result = (|| {
            let path = application_data()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Unavailable)?;
            let r = runtime.block_on(crate::installed_cli_ipc::request(&path, &request))?;
            output(&r, &a.origin, a.json)
        })();
        Ok(result.unwrap_or_else(|_|{let mut b=if a.json{serde_json::to_vec(&serde_json::json!({"ok":false,"error":"state_unknown","origin":a.origin,"doNotReplay":true})).unwrap_or_default()}else{format!("Acknowledgement unconfirmed. Do not repeat Read/Prepare. {receipt}").into_bytes()};b.push(b'\n');(6,b)}))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = a;
        Err(Error::UnsupportedPlatform)
    }
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    let json = args.iter().any(|s| s == "--json");
    let (code, b) = parse(&args)
        .and_then(execute)
        .unwrap_or_else(|e| (exit_code(e), error_bytes(e, json)));
    if std::io::stdout().write_all(&b).is_err() {
        6
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_metadata_images_protocol::fixtures::*;
    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }
    #[test]
    fn fixed_read_prepare_collectors_require_original_ids_and_bounded_stdin_choices() {
        let q = query();
        let ids = [
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ];
        let a = args(&["metadata-images-read", ids[0], ids[1], ids[2], "--json"]);
        assert!(recognizes(&a));
        assert!(!parse(&a).unwrap().prepare);
        let a = args(&["metadata-images-prepare", ids[0], ids[1], ids[2], "--stdin"]);
        assert!(parse(&a).unwrap().prepare);
        for flag in ["--file", "--reviewed", "--force", "--path"] {
            assert!(parse(&args(&[
                "metadata-images-prepare",
                ids[0],
                ids[1],
                ids[2],
                flag
            ]))
            .is_err());
        }
        let input = c::fixtures::prepare(3);
        let value = serde_json::json!({"observationRevision":3,"openedSha256":input.opened_sha256,"choices":input.choices});
        let raw = serde_json::to_vec(&value).unwrap();
        assert_eq!(fields(raw.as_slice(), q.clone()).unwrap(), input);
        assert!(fields(&vec![b' '; c::REQUEST_BYTES + 1][..], q.clone()).is_err());
        assert!(fields(br#"{"choices":[],"choices":[]}"#.as_slice(), q.clone()).is_err());
        let mut private = value;
        private["path"] = serde_json::json!("/tmp/image");
        assert!(fields(serde_json::to_vec(&private).unwrap().as_slice(), q).is_err());
    }
    #[test]
    fn actual_response_variant_keeps_preparation_separate_from_apply_permission() {
        let (e, _a, _w) = crate::service_metadata_images_prepare_requests::fixtures::entry();
        let status = e.status().unwrap();
        let response = p::Response {
            version: p::VERSION,
            request_id: id('e'),
            service_instance: id('1'),
            client_id: id('2'),
            session_id: id('3'),
            response: p::ResponseBody::MetadataImagesPreparation(status),
        };
        assert!(output(&response, &query(), false).is_ok());
        let text = String::from_utf8(output(&response, &query(), false).unwrap().1).unwrap();
        assert!(text.contains("Recovery"));
        let mut wrong = query();
        wrong.request_id = id('f');
        assert!(output(&response, &wrong, true).is_err());
        let r = p::Response {
            response: p::ResponseBody::MetadataImagesRequest(
                crate::service_metadata_images_protocol::fixtures::status(),
            ),
            ..response
        };
        assert!(output(&r, &query(), true).is_err());
    }
}
