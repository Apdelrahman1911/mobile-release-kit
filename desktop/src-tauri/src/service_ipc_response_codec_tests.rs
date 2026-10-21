//! Actual codec/closed DTO tests only. No Service, socket, file or native owner.
use super::*;
use crate::{service_metadata_text_protocol as m, service_setup_guidance as g};

fn id(n: usize) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn response(body: ResponseBody) -> Response {
    Response {
        version: VERSION,
        request_id: id(1),
        service_instance: id(2),
        client_id: id(3),
        session_id: id(4),
        response: body,
    }
}
fn original_encoder(value: &Response) -> Result<Vec<u8>, Error> {
    // The unchanged pre-amendment validation/error path, for byte equivalence.
    validate_response(value)?;
    let bytes = if matches!(&value.response, ResponseBody::MetadataTextRequest(_)) {
        m::encoded(value, RESPONSE_BYTES).map_err(|_| Error::StateUnknown)?
    } else {
        serde_json::to_vec(value).map_err(|_| Error::StateUnknown)?
    };
    if bytes.len() > RESPONSE_BYTES {
        return Err(Error::StateUnknown);
    }
    Ok(bytes)
}
fn same_bytes(value: &Response) -> Vec<u8> {
    let old = original_encoder(value).unwrap();
    let bytes = encode_response(value).unwrap();
    assert_eq!(bytes, old);
    assert_eq!(bytes.capacity(), bytes.len());
    assert_eq!(
        decode_response(&bytes, &value.request_id, &value.service_instance).unwrap(),
        *value
    );
    bytes
}
fn info() -> Response {
    response(ResponseBody::Info(ServiceInfo {
        read_only: false,
        read_grant_authorizes_execution: false,
        local_checks_require_separate_grant: true,
        requires_running_desktop: true,
        cached_observations_are_authority: false,
        remaining_access_ms: 3_600_000,
    }))
}
fn guidance() -> g::SetupAnalysis {
    // Reuse the existing fixed provider-free guidance fixture and real
    // projection rather than constructing a producer-impossible enum roster.
    g::project(
        Some(&g::fixture(
            &[g::Platform::Android, g::Platform::Ios],
            ConfigurationState::FormatValid,
            false,
        )),
        ConfigurationState::FormatValid,
        false,
    )
    .unwrap()
}
fn project(n: usize) -> ProjectObservation {
    ProjectObservation {
        project_id: id(n),
        registered_in_current_host: false,
        observation: Some(SavedObservation {
            revision: u64::MAX,
            stale: false,
            configuration: SavedConfiguration {
                state: ConfigurationState::FormatValid,
                bytes: Some(1024 * 1024),
                sha256: Some("a".repeat(64)),
            },
            discovery_partial: false,
            issue_count: 20_000,
            setup_analysis: Some(guidance()),
        }),
    }
}
fn metadata() -> Response {
    let platform = m::Platform::Ios;
    // Five real typed text fields, exact matching hash/byte-length/baseline.
    // This is synthetic DATA, not a native Load receipt or writable source.
    let text = "😀".repeat(m::TEXT_BYTES / 4);
    let hash = m::sha(text.as_bytes());
    let observation = m::Observation {
        schema_version: 1,
        platform,
        locale: "en-US".into(),
        metadata_root: "release/store".into(),
        observation_scope: "single-request-non-atomic".into(),
        baseline: m::Baseline {
            config: m::DigestData {
                byte_length: 2,
                sha256: m::sha(b"{}"),
            },
            fields: platform
                .ids()
                .iter()
                .map(|v| m::BaselineField::Present {
                    id: (*v).into(),
                    byte_length: text.len() as u32,
                    sha256: hash.clone(),
                })
                .collect(),
        },
        fields: platform
            .ids()
            .iter()
            .map(|v| m::ObservedField::Present {
                id: (*v).into(),
                path: format!("release/store/ios/en-US/{v}"),
                text: text.clone(),
                byte_length: text.len() as u32,
                sha256: hash.clone(),
            })
            .collect(),
        assurance: m::Assurance {
            basis: "static-text".into(),
            project_code_executed: false,
            tools_probed: false,
            credentials_read: false,
            git_observed: false,
            store_contacted: false,
            writes_performed: false,
            release_readiness: "unknown".into(),
        },
    };
    response(ResponseBody::MetadataTextRequest(m::Status {
        schema_version: 1,
        origin: m::Query {
            service_instance: id(2),
            project_id: id(5),
            request_id: id(6),
        },
        revision: 1,
        runtime_project_id: "project-1".into(),
        platform,
        locale: "en-US".into(),
        phase: m::Phase::Loaded,
        observation: Some(observation),
        original: None,
        proposal_sha256: None,
        review: None,
        permission_live: false,
        remaining_ms: 0,
        apply_consumed: false,
        cancel_requested: false,
        result: None,
        do_not_replay: true,
    }))
}

#[test]
fn outer_fixed_encoder_preserves_old_envelopes_bytes_and_exact_capacity() {
    same_bytes(&info());
    for error in [
        Error::InvalidRequest,
        Error::AccessDenied,
        Error::StateUnknown,
        Error::Busy,
    ] {
        same_bytes(&response(ResponseBody::Error(error)));
    }
    same_bytes(&response(ResponseBody::GitIndexScope(
        crate::service_git_protocol::Scope {
            service_instance: id(2),
            project_id: id(5),
            access: crate::service_git_protocol::Access::empty(),
        },
    )));
    same_bytes(&response(ResponseBody::Projects(Vec::new())));
    same_bytes(&response(ResponseBody::Operations(Vec::new())));
}

#[test]
fn largest_closed_generic_lists_fit_the_source_derived_wire_and_typed_roster() {
    let projects = response(ResponseBody::Projects(
        (1..=PROJECT_LIMIT).map(project).collect(),
    ));
    let bytes = same_bytes(&projects);
    assert!(bytes.len() <= 512 + PROJECT_LIMIT * (1863 + 1));
    let operations = response(ResponseBody::Operations(
        (1..=OPERATION_LIMIT)
            .map(|n| OperationObservation {
                operation_id: id(n),
                project_id: id(1),
                action: Action::GitHubRepositoryCreate,
                state: OperationState::CancellationRequested,
                settlement: Settlement::Pending,
                observation_revision: u64::MAX,
                stale: false,
            })
            .collect(),
    ));
    let bytes = same_bytes(&operations);
    assert!(bytes.len() <= 512 + OPERATION_LIMIT * (254 + 1));
    // Both were actually encoded, not accepted merely because fields were small.
    assert!(bytes.len() > 32 * 1024);
}

#[test]
fn metadata_full_text_keeps_the_same_fixed_encoder_and_never_changes_frame_limits() {
    let value = metadata();
    let bytes = same_bytes(&value);
    assert!(bytes.len() > 128 * 1024 && bytes.len() < RESPONSE_BYTES);
    assert_eq!(RESPONSE_BYTES, 256 * 1024);
    assert_eq!(REQUEST_BYTES, 4096);
    let mut bad = value;
    if let ResponseBody::MetadataTextRequest(status) = &mut bad.response {
        if let m::ObservedField::Present { text, .. } =
            &mut status.observation.as_mut().unwrap().fields[0]
        {
            text.push('x'); // true hash/byte-length mismatch is still refused
        }
    }
    assert_eq!(encode_response(&bad), original_encoder(&bad));
    assert!(encode_response(&bad).is_err());
}

#[test]
fn validation_and_oversize_errors_are_identical_without_growable_outer_output() {
    let mut invalid = info();
    invalid.version = VERSION + 1;
    assert_eq!(encode_response(&invalid), Err(Error::InvalidRequest));
    assert_eq!(encode_response(&invalid), original_encoder(&invalid));
    let repeated = response(ResponseBody::Projects(vec![project(1), project(1)]));
    assert_eq!(encode_response(&repeated), Err(Error::InvalidRequest));
    assert_eq!(encode_response(&repeated), original_encoder(&repeated));
    let mut denied = info();
    if let ResponseBody::Info(v) = &mut denied.response {
        v.read_grant_authorizes_execution = true;
    }
    assert_eq!(encode_response(&denied), original_encoder(&denied));
    assert!(encode_response(&denied).is_err());

    // Deliberately producer-invalid DATA: the existing base project validator
    // does not validate optional guidance. Preserve its old outer-size error,
    // but the new counted first pass refuses BEFORE allocating that output.
    // No application source or actual saved-observation producer creates this.
    let mut huge = project(1);
    let g = huge
        .observation
        .as_mut()
        .unwrap()
        .setup_analysis
        .as_mut()
        .unwrap();
    g.requirements = vec![g.requirements[0].clone(); 5000];
    let huge = response(ResponseBody::Observation(huge));
    assert_eq!(validate_response(&huge), Ok(()));
    assert_eq!(original_encoder(&huge), Err(Error::StateUnknown));
    assert_eq!(encode_response(&huge), Err(Error::StateUnknown));
}
