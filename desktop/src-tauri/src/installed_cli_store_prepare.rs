//! Two fixed, ID-only phase calls on the existing Store client. No context,
//! credential/path selection, provider endpoint or automatic second call.
use super::*;
use crate::service_store_prepare_protocol as flow;
pub(super) enum Command {
    Prepare {
        project: Id,
        instance: Id,
        grant: Id,
        review: Id,
    },
    Start {
        origin: store::Query,
        grant: Id,
        review: Id,
    },
}
pub(super) fn parse(words: &[&str]) -> Result<Command, Error> {
    match words {
        ["store-prepare", project, instance, grant, review, "--reviewed"] => Ok(Command::Prepare {
            project: Id::parse(project)?,
            instance: Id::parse(instance)?,
            grant: Id::parse(grant)?,
            review: Id::parse(review)?,
        }),
        ["store-start", project, instance, request, grant, review, "--reviewed"] => {
            Ok(Command::Start {
                origin: store::Query {
                    project_id: Id::parse(project)?,
                    service_instance: Id::parse(instance)?,
                    request_id: Id::parse(request)?,
                },
                grant: Id::parse(grant)?,
                review: Id::parse(review)?,
            })
        }
        _ => Err(Error::InvalidRequest),
    }
}
pub(super) fn output(
    response: &p::Response,
    q: &store::Query,
    expected: Option<(bool, &Id, &Id)>,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    if let p::ResponseBody::Error(e) = response.response {
        return Err(e);
    }
    let p::ResponseBody::StorePreparation(s) = &response.response else {
        return Err(Error::StateUnknown);
    };
    s.validate()?;
    if s.origin != *q
        || response.service_instance != q.service_instance
        || expected.is_some_and(|(start, g, r)| {
            if start {
                !s.start_submitted
                    || s.start_grant_id.as_ref() != Some(g)
                    || s.prepared.as_ref().is_none_or(|v| &v.review_id != r)
            } else {
                &s.prepare_grant_id != g || &s.selection_id != r
            }
        })
    {
        return Err(Error::StateUnknown);
    }
    let code = if s.phase == flow::Phase::Unknown {
        6
    } else if s.phase == flow::Phase::Final && s.outcome != Some(store::Outcome::Complete) {
        5
    } else {
        0
    };
    let bytes = if json {
        let mut b = p::encode_response(response)?;
        b.push(b'\n');
        b
    } else {
        let mut t = format!(
            "Store preparation: {:?}; {:?}.\n{}",
            s.phase,
            s.settlement,
            receipt(q)
        );
        t.push_str("Prepare does not start a Store call. Starting needs a new explicit Desktop approval of this returned native Prepared. No automatic second phase or retry.\n");
        if let Some(flow::Report::CurrentVersions { inventory }) = &s.result {
            t.push_str(&format!(
                "Current-visible inventory DATA: {}\n",
                serde_json::to_string(inventory).map_err(|_| Error::InvalidRequest)?
            ));
            t.push_str("A completed call may still be inconclusive. This does not prove historical uniqueness, allocate a version, or authorize a retry. Paired inventories are not an atomic cross-store snapshot.\n");
        }
        t.into_bytes()
    };
    Ok((code, bytes))
}
pub(super) fn execute(command: Command, json: bool) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (q, grant, review, start) = match command {
            Command::Prepare {
                project,
                instance,
                grant,
                review,
            } => (
                store::Query {
                    project_id: project,
                    service_instance: instance,
                    request_id: Id::random()?,
                },
                grant,
                review,
                false,
            ),
            Command::Start {
                origin,
                grant,
                review,
            } => (origin, grant, review, true),
        };
        // Retain public correlation before the first original transport call.
        std::io::stderr()
            .write_all(receipt(&q).as_bytes())
            .map_err(|_| Error::Unavailable)?;
        let input = flow::Submit {
            origin: q.clone(),
            grant_id: grant.clone(),
            review_id: review.clone(),
        };
        let body = if start {
            p::RequestBody::StoreStart(input)
        } else {
            p::RequestBody::StorePrepare(input)
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
            output(&response, &q, Some((start, &grant, &review)), json)
        })();
        match result {
            Ok(v) => Ok(v),
            Err(e) => Ok((6, unconfirmed(&q, e, json))),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (command, json);
        Err(Error::UnsupportedPlatform)
    }
}
