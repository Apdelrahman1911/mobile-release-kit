//! Native DATA adapters over existing tool owners. There is deliberately no
//! Deserialize implementation for Observation and no path/argv/installer API.
//! Root calls this with statuses obtained from its ORIGINAL document owners,
//! never renderer-supplied Status-shaped JSON. Execution stays in those owners.
use crate::{android_build_protocol as build, android_registration_app_protocol as registration,
    android_tool_sources as sources, android_toolchain_catalog as catalog,
    environment_diagnostics_protocol as diagnostics, tool_preparation as plan};

pub(crate) fn current_host() -> plan::Host {
    match build::Profile::current() {
        Some(build::Profile::MacArm64) => plan::Host::MacArm64,
        Some(build::Profile::MacX64) => plan::Host::MacX64,
        Some(build::Profile::LinuxX64) => plan::Host::LinuxX64, None => plan::Host::Other,
    }
}
fn versions(value: &catalog::Versions) -> plan::Versions {
    plan::Versions { jdk_vendor: value.jdk_vendor.clone(), jdk: value.jdk_version.clone(), gradle: value.gradle_version.clone(),
        agp: value.agp_version.clone(), sdk_platform: value.sdk_platform.clone(), sdk_build_tools: value.sdk_build_tools_version.clone() }
}
fn comparison(value: &build::MacToolchainSelection) -> plan::Comparison {
    plan::Comparison { instance: value.instance.clone(), record_sha256: value.record_sha256.clone(),
        inventory_sha256: value.inventory_sha256.clone(), os_provider_sha256: value.os_provider_sha256.clone() }
}
fn role(value: sources::Role) -> plan::Role {
    match value { sources::Role::Jdk => plan::Role::Jdk, sources::Role::Sdk => plan::Role::Sdk, sources::Role::Gradle => plan::Role::Gradle }
}
fn elevate(activity: &mut plan::Activity, candidate: plan::Activity) {
    let rank = |v| match v { plan::Activity::Idle => 0, plan::Activity::Unavailable => 1, plan::Activity::Busy => 2, plan::Activity::Unknown => 3 };
    if rank(candidate) > rank(*activity) { *activity = candidate; }
}
fn gate(value: build::Availability) -> plan::Activity {
    match value {
        build::Availability::CleanupUnknown => plan::Activity::Unknown,
        build::Availability::Busy => plan::Activity::Busy,
        build::Availability::Shutdown | build::Availability::DocumentLost | build::Availability::UnsupportedPlatform
            | build::Availability::RuntimeUnqualified => plan::Activity::Unavailable,
        // The existing catalog/source setup can explain missing tool selection;
        // this does NOT promote ToolchainUnqualified into execution availability.
        build::Availability::Available | build::Availability::ToolchainUnqualified => plan::Activity::Idle,
    }
}
fn empty(host: plan::Host) -> plan::Observation {
    plan::Observation { host, stamp: plan::Stamp::default(), activity: plan::Activity::Idle,
        catalog: plan::CatalogState::NotChecked, copies: vec![], selected: None, picked: vec![],
        inspection: plan::Inspection::NotInspected, complete_source_review: false,
        service: plan::Service::NotChecked, source_picker_available: false, policies: vec![],
        xcode_state: plan::XcodeState::NotChecked, xcode_observed: None }
}

pub(crate) fn android_observation(saved: &build::Prepare, tools: &catalog::Status,
    picked: &sources::Status, inspection: &registration::Status, service: &registration::ServiceStatus,
) -> Result<plan::Observation, plan::Error> {
    let mut result = empty(current_host());
    if [tools.schema_version, picked.schema_version, inspection.schema_version, service.schema_version] != [1; 4]
        || tools.entries.len() > catalog::ENTRY_LIMIT || picked.selections.len() > 3 {
        return Err(plan::Error::InvalidObservation);
    }
    result.stamp = plan::Stamp { catalog_generation: tools.catalog_generation, catalog_revision: tools.status_revision,
        source_generation: picked.source_generation, source_revision: picked.status_revision,
        registration_generation: inspection.registration_generation, registration_revision: inspection.status_revision,
        service_generation: service.setup_generation, service_revision: service.status_revision, diagnostics_revision: 0 };
    result.activity = gate(tools.availability);
    // Unsettled ORIGINALS remain blockers even if they belong to a previous
    // project. A project switch cannot discard a native copy or picker owner.
    for activity in [gate(picked.availability), gate(inspection.availability), gate(service.availability)] {
        if matches!(activity, plan::Activity::Unknown | plan::Activity::Busy) { elevate(&mut result.activity, activity); }
    }
    match tools.phase {
        catalog::Phase::Unknown => elevate(&mut result.activity, plan::Activity::Unknown),
        catalog::Phase::Reading | catalog::Phase::Stopping => elevate(&mut result.activity, plan::Activity::Busy),
        catalog::Phase::Ready => result.catalog = plan::CatalogState::Ready,
        catalog::Phase::Refused => result.catalog = plan::CatalogState::Refused, _ => {},
    }
    if tools.phase == catalog::Phase::Ready {
        for row in &tools.entries {
            if !row.valid(tools.catalog_generation) { return Err(plan::Error::InvalidObservation); }
            result.copies.push(plan::Copy {
                state: match row.status { catalog::RowStatus::VerifiedThisSession => plan::CopyState::Verified,
                    catalog::RowStatus::RecoveryRequired => plan::CopyState::RecoveryRequired, catalog::RowStatus::Busy => plan::CopyState::Busy,
                    catalog::RowStatus::Interrupted => plan::CopyState::Interrupted, catalog::RowStatus::Refused => plan::CopyState::Refused },
                versions: row.versions.as_ref().map(versions),
                comparison: row.selection.as_ref().map(comparison).or_else(|| row.recovery.as_ref().map(|value| plan::Comparison {
                    instance: value.instance.clone(), record_sha256: value.record_sha256.clone(),
                    inventory_sha256: value.inventory_sha256.clone(), os_provider_sha256: value.os_provider_sha256.clone() })),
            });
        }
        if let Some(selected) = &tools.selected {
            if !selected.valid() || selected.catalog_generation != tools.catalog_generation
                || !tools.entries.iter().any(|row| row.selection.as_ref() == Some(selected)) {
                return Err(plan::Error::InvalidObservation);
            }
            result.selected = Some(comparison(selected));
        }
    }
    match picked.phase {
        sources::Phase::Unknown => elevate(&mut result.activity, plan::Activity::Unknown),
        sources::Phase::Picking | sources::Phase::Checking | sources::Phase::Stopping => elevate(&mut result.activity, plan::Activity::Busy), _ => {},
    }
    result.source_picker_available = picked.availability == build::Availability::Available;
    if picked.project_id.as_deref() == Some(saved.project_id.as_str()) && picked.phase == sources::Phase::Selected {
        result.picked = picked.selections.iter().map(|selected| role(selected.role)).collect();
    }
    match inspection.phase {
        registration::Phase::Unknown => elevate(&mut result.activity, plan::Activity::Unknown),
        registration::Phase::Inspecting | registration::Phase::Preparing | registration::Phase::Copying | registration::Phase::Verifying
            | registration::Phase::Publishing | registration::Phase::Settling | registration::Phase::Stopping => elevate(&mut result.activity, plan::Activity::Busy), _ => {},
    }
    if inspection.report.as_ref().is_some_and(|report| report.protected_copy == registration::ProtectedCopy::RetainedPartial) {
        result.inspection = plan::Inspection::RetainedPartial;
    } else if inspection.operation.as_ref().is_some_and(|operation| &operation.context == saved && operation.source_generation == picked.source_generation) {
        if inspection.phase == registration::Phase::Complete
            && inspection.report.as_ref().is_some_and(|report| report.protected_copy == registration::ProtectedCopy::Published) {
            result.inspection = plan::Inspection::Published;
        } else if inspection.phase == registration::Phase::Refused {
            result.inspection = plan::Inspection::Refused;
        } else if inspection.phase == registration::Phase::Review {
            result.inspection = plan::Inspection::Review;
            result.complete_source_review = inspection.review.as_ref().is_some_and(|review| &review.context == saved
                && review.source_generation == picked.source_generation && review.sources.len() == 3
                && [sources::Role::Jdk, sources::Role::Sdk, sources::Role::Gradle].into_iter().all(|role|
                    review.sources.iter().filter(|source| source.role == role).count() == 1)
                && review.sources.iter().all(|source| source.complete && source.version.is_some()
                    && source.compatibility == registration::Compatibility::Compatible));
        }
    }
    match service.phase {
        registration::ServicePhase::Unknown => elevate(&mut result.activity, plan::Activity::Unknown),
        registration::ServicePhase::Checking | registration::ServicePhase::Requesting | registration::ServicePhase::OpeningSettings
            | registration::ServicePhase::Settling | registration::ServicePhase::Stopping => elevate(&mut result.activity, plan::Activity::Busy), _ => {},
    }
    if let Some(observation) = &service.observation {
        if observation.mutation_uncertain || !observation.native_settled {
            elevate(&mut result.activity, plan::Activity::Unknown);
        } else if service.phase == registration::ServicePhase::Complete
            && service.operation.as_ref().is_some_and(|operation| &operation.context == saved && operation.source_generation == picked.source_generation) {
            // A returned registration request is not a fresh enabled-state Check.
            result.service = match observation.state {
                registration::ServiceState::Enabled if service.operation.as_ref().is_some_and(|operation| operation.action == registration::ServiceAction::Check)
                    && observation.outcome == registration::ServiceOutcome::Observed => plan::Service::Enabled,
                registration::ServiceState::RequiresApproval => plan::Service::NeedsApproval,
                registration::ServiceState::NotRegistered => plan::Service::NeedsRegistration,
                _ => plan::Service::NotChecked,
            };
        }
    }
    #[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    if let Some(profile) = build::Profile::current() {
        // Already-warm source policy only. No catalogue initialisation/IO under
        // the document's observation locks and no cross-architecture fallback.
        if let Some(policies) = crate::android_supplier_macos::preparation_policies_for(profile) {
            result.policies = policies.into_iter().map(|policy| plan::Policy { host: result.host,
                versions: versions(&policy.versions), distribution: plan::Distribution {
                    url: policy.distribution_url.into(), sha256: policy.distribution_sha256.into() } }).collect();
        }
    }
    Ok(result)
}

pub(crate) fn ios_observation(expected: &diagnostics::Context, status: &diagnostics::Status) -> Result<plan::Observation, plan::Error> {
    if status.schema_version != 1 || expected.platform != diagnostics::Platform::Ios { return Err(plan::Error::InvalidObservation); }
    let mut result = empty(current_host()); result.stamp.diagnostics_revision = status.status_revision;
    match status.capability.reason {
        diagnostics::Availability::CleanupUnknown => result.activity = plan::Activity::Unknown,
        diagnostics::Availability::Busy => result.activity = plan::Activity::Busy,
        diagnostics::Availability::Available => {}, _ => result.activity = plan::Activity::Unavailable,
    }
    if let Some(active) = &status.active {
        elevate(&mut result.activity, if active.finality == diagnostics::Finality::Unknown { plan::Activity::Unknown } else { plan::Activity::Busy });
        return Ok(result);
    }
    let Some(original) = &status.last_terminal else { return Ok(result); };
    if original.finality == diagnostics::Finality::Unknown { result.activity = plan::Activity::Unknown; return Ok(result); }
    if &original.context != expected { return Ok(result); }
    if original.finality != diagnostics::Finality::Settled || original.phase != diagnostics::Phase::Settled {
        result.activity = plan::Activity::Unknown; return Ok(result);
    }
    if !matches!(original.outcome, Some(diagnostics::Outcome::Complete | diagnostics::Outcome::Partial))
        || original.reason != diagnostics::Reason::None { return Ok(result); }
    let Some(terminal) = &original.result else { return Ok(result); };
    if !terminal.lifetime.settled() { result.activity = plan::Activity::Unknown; return Ok(result); }
    if let Some((reason, pin)) = terminal.xcode_preparation_hint() {
        if let Some((version, build)) = pin {
            result.xcode_state = plan::XcodeState::Observed;
            result.xcode_observed = Some(plan::XcodePin { version: version.into(), build: build.into() });
        } else {
            result.xcode_state = match reason {
                diagnostics::CheckReason::MissingInSupportedLookup | diagnostics::CheckReason::FullXcodeNotSelected => plan::XcodeState::Missing,
                _ => plan::XcodeState::Unavailable,
            };
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    // Existing protocol structures as inert DATA only. These tests never mint
    // an original owner, picker, installed tool, finality receipt or lease.
    use super::*;
    use serde_json::json;
    fn fixture() -> (build::Prepare, catalog::Status, sources::Status, registration::Status, registration::ServiceStatus) {
        let saved = build::prepare(&json!({"projectId":"project-a","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":1,"sha256":"a".repeat(64)},"savedVersion":{"source":"VERSION","bytes":1,"sha256":"b".repeat(64),"name":"1.0","build":1},
            "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})).unwrap();
        let tools = catalog::Status { schema_version:1,status_revision:2,catalog_generation:1,operation_id:Some("a".repeat(32)),
            availability:build::Availability::Available,phase:catalog::Phase::Ready,reason:catalog::Reason::None,entries:vec![],selected:None };
        let roles = [sources::Role::Jdk,sources::Role::Sdk,sources::Role::Gradle];
        let picked = sources::Status {schema_version:1,status_revision:3,source_generation:1,project_id:Some(saved.project_id.clone()),
            availability:build::Availability::Available,phase:sources::Phase::Selected,reason:sources::Reason::None,
            operation:Some(sources::Operation {operation_id:3,source_generation:1,role:sources::Role::Gradle}),
            selections:roles.map(|role|sources::Selection {role,display_name:"inert folder label".into()}).to_vec(),inspection:"not-run",protected_copy:"not-created"};
        let inspection = registration::Status {schema_version:1,status_revision:4,registration_generation:1,availability:build::Availability::Available,
            prerequisite:registration::Prerequisite::Ready,phase:registration::Phase::Review,reason:registration::Reason::None,
            operation:Some(registration::Operation {operation_id:"b".repeat(32),registration_generation:1,source_generation:1,kind:registration::Kind::Inspection,context:saved.clone()}),
            review:Some(registration::Review {review_id:"c".repeat(32),source_generation:1,context:saved.clone(),consent_version:registration::CONSENT,
                license_acknowledgment_required:true,sources:roles.map(|role|registration::Source {role,version:Some("17.0.1".into()),logical_bytes:1,files:1,entries:1,
                    aliases:0,complete:true,compatibility:registration::Compatibility::Compatible}).to_vec()}),report:None};
        let service = registration::ServiceStatus {schema_version:1,status_revision:2,setup_generation:1,availability:build::Availability::Available,
            prerequisite:registration::Prerequisite::Ready,phase:registration::ServicePhase::Complete,reason:registration::Reason::None,
            identity_failure:None,
            operation:Some(registration::ServiceOperation {operation_id:"d".repeat(32),setup_generation:1,source_generation:1,action:registration::ServiceAction::Check,context:saved.clone()}),
            observation:Some(registration::ServiceObservation {state:registration::ServiceState::Enabled,outcome:registration::ServiceOutcome::Observed,
                mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true})};
        (saved,tools,picked,inspection,service)
    }
    #[test]
    fn selected_picker_keeps_its_last_original_but_is_not_source_inspection() {
        let (saved,tools,picked,mut inspection,service) = fixture();
        let observed = android_observation(&saved,&tools,&picked,&inspection,&service).unwrap();
        assert_eq!(observed.picked,vec![plan::Role::Jdk,plan::Role::Sdk,plan::Role::Gradle]);
        assert!(observed.complete_source_review); assert_eq!(observed.service,plan::Service::Enabled);
        inspection.phase = registration::Phase::Idle; inspection.review = None;
        assert!(!android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().complete_source_review);
    }
    #[test]
    fn compatible_looking_partial_or_wrong_source_context_never_completes_review() {
        for change in 0..5 {
            let (saved,tools,picked,mut inspection,service) = fixture();
            let review = inspection.review.as_mut().unwrap();
            match change {0=>review.sources[0].complete=false,1=>review.sources[0].version=None,
                2=>review.sources[1].role=sources::Role::Jdk,3=>review.source_generation+=1,
                _=>review.context.saved_config.sha256="f".repeat(64)}
            assert!(!android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().complete_source_review);
        }
    }
    #[test]
    fn registration_reply_is_not_a_fresh_enabled_check_and_unsettled_mutation_is_retained() {
        let (saved,tools,picked,inspection,mut service) = fixture();
        service.operation.as_mut().unwrap().action=registration::ServiceAction::RequestRegistration;
        service.observation.as_mut().unwrap().outcome=registration::ServiceOutcome::RegistrationRequested;
        assert_eq!(android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().service,plan::Service::NotChecked);
        service.observation.as_mut().unwrap().native_settled=false;
        assert_eq!(android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().activity,plan::Activity::Unknown);
        service.observation=None; service.phase=registration::ServicePhase::Settling;
        assert_eq!(android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().activity,plan::Activity::Busy);
    }
    #[test]
    fn retained_partial_from_another_project_is_not_cleared_by_selection() {
        let (saved,tools,picked,mut inspection,service) = fixture();
        inspection.phase=registration::Phase::Refused; inspection.operation.as_mut().unwrap().context.project_id="project-b".into();
        inspection.report=Some(registration::Report {sources:vec![],protected_copy:registration::ProtectedCopy::RetainedPartial,accounting:None,
            problems:registration::Problems {recorded:0,shown:0,omitted:0,first:None,items:vec![]}});
        assert_eq!(android_observation(&saved,&tools,&picked,&inspection,&service).unwrap().inspection,plan::Inspection::RetainedPartial);
    }
    #[test]
    fn xcode_hint_requires_original_settled_projection_not_just_terminal_bytes() {
        let context = diagnostics::Context {project_id:"project-a".into(),draft_revision:1,baseline_generation:2,platform:diagnostics::Platform::Ios,operation:diagnostics::Operation::Build};
        let mut terminal = diagnostics::tests::terminal(&context);
        terminal["hostPlatform"] = json!("macos");
        terminal["checks"] = json!([{"id":"xcode","state":"completed","reason":"observed","version":"26.3","build":"17C529","returnCode":0,
            "baseline":{"kind":"exact-pin","version":"26.3","build":"17C529"},"assessment":"match","help":"Inert adapter input"}]);
        let row = diagnostics::Projection {run_id:"a".repeat(32),owner_generation:"b".repeat(32),context:context.clone(),phase:diagnostics::Phase::Settled,
            outcome:Some(diagnostics::Outcome::Complete),finality:diagnostics::Finality::Settled,reason:diagnostics::Reason::None,
            result:Some(serde_json::from_value(terminal.clone()).unwrap())};
        let mut status = diagnostics::Status {schema_version:1,status_revision:1,capability:diagnostics::Capability {available:true,reason:diagnostics::Availability::Available},active:None,last_terminal:Some(row)};
        assert_eq!(ios_observation(&context,&status).unwrap().xcode_state,plan::XcodeState::Observed);
        status.last_terminal.as_mut().unwrap().finality=diagnostics::Finality::Pending;
        assert_eq!(ios_observation(&context,&status).unwrap().activity,plan::Activity::Unknown);
        status.last_terminal.as_mut().unwrap().finality=diagnostics::Finality::Settled;
        status.last_terminal.as_mut().unwrap().context.draft_revision+=1;
        assert_eq!(ios_observation(&context,&status).unwrap().xcode_state,plan::XcodeState::NotChecked);
        status.last_terminal.as_mut().unwrap().context=context.clone();
        terminal["lifetime"]["toolDescriptorsClosed"]=json!(false);
        status.last_terminal.as_mut().unwrap().result=Some(serde_json::from_value(terminal).unwrap());
        assert_eq!(ios_observation(&context,&status).unwrap().activity,plan::Activity::Unknown);
    }
}
