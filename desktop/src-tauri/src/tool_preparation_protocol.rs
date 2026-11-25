//! Fixed read-only planning wire. A request nominates only a saved project and
//! expected observation; native adapters never accept client-supplied tool state.
use crate::{error::BridgeError, protocol::strict_json, tool_preparation as plan};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

const REQUIREMENTS_LIMIT: usize = 16 * 1024;
fn gradle_distribution(version: &str, url: &str, digest: Option<&str>) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    (2..=3).contains(&parts.len()) && version.len() <= 64 && parts.iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && ["https://services.gradle.org/distributions/", "https://downloads.gradle.org/distributions/"]
            .into_iter().any(|prefix| url == format!("{prefix}gradle-{version}-bin.zip"))
        && digest.is_none_or(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) schema_version: u32, pub(crate) project_id: String,
    pub(crate) expected_observation_revision: u32,
}
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("tool_preparation_invalid", "Check the selected project's current build-tool requirements again.")
}
pub(crate) fn request(raw: &[u8]) -> Result<Request, BridgeError> {
    if raw.len() > 1024 { return Err(invalid()); }
    let value: Request = serde_json::from_value(strict_json(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
    if value.schema_version != 1 || !crate::protocol::valid_id(&value.project_id)
        || value.expected_observation_revision == 0 || value.expected_observation_revision == u32::MAX { return Err(invalid()); }
    Ok(value)
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> { Option::<T>::deserialize(d) }
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum HintState { Literal, Unspecified, Unknown }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hint { state: HintState, #[serde(deserialize_with = "present")] value: Option<String> }
impl Hint {
    fn into_constraint(self, optional: bool) -> Result<plan::Constraint, BridgeError> {
        match (self.state, self.value) {
            (HintState::Literal, Some(value)) if !value.is_empty() && value.len() <= 128
                && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) => Ok(plan::Constraint::Literal(value)),
            (HintState::Unspecified, None) if optional => Ok(plan::Constraint::Unspecified),
            (HintState::Unknown, None) => Ok(plan::Constraint::Unknown), _ => Err(invalid()),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Gradle {
    state: HintState, #[serde(deserialize_with = "present")] version: Option<String>,
    #[serde(deserialize_with = "present")] distribution_url: Option<String>,
    #[serde(deserialize_with = "present")] sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Android { jdk: Hint, agp: Hint, sdk_platform: Hint, sdk_build_tools: Hint, gradle: Gradle }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Xcode { version: String, build: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Requirements {
    schema_version: u32, basis: String, sources_sha256: String, complete: bool, platform: String,
    project_code_executed: bool, #[serde(deserialize_with = "present")] android: Option<Android>, xcode: Xcode,
}
/// Decode only the actual bounded core source-hint response. This function does
/// not own the source; Root compares the full saved snapshot before publication.
pub(crate) fn requirements(raw: &[u8]) -> Result<(String, plan::Requirements), BridgeError> {
    if raw.len() > REQUIREMENTS_LIMIT { return Err(invalid()); }
    let value: Requirements = serde_json::from_value(strict_json(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
    if value.schema_version != 1 || value.basis != "unverified-static-source-hints" || value.project_code_executed
        || value.sources_sha256.len() != 64 || !value.sources_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid());
    }
    let platform = match value.platform.as_str() { "android" => plan::Platform::Android, "ios" => plan::Platform::Ios, _ => return Err(invalid()) };
    let android = if let Some(android) = value.android {
        if platform != plan::Platform::Android { return Err(invalid()); }
        let (gradle, distribution) = match (android.gradle.state, android.gradle.version, android.gradle.distribution_url, android.gradle.sha256) {
            (HintState::Unknown, None, None, None) => (plan::Constraint::Unknown, None),
            (HintState::Literal, Some(version), Some(url), digest) if url.len() <= 256 && gradle_distribution(&version, &url, digest.as_deref()) =>
                (plan::Constraint::Literal(version), digest.map(|sha256| plan::Distribution { url, sha256 })),
            _ => return Err(invalid()),
        };
        Some(plan::AndroidRequirements { jdk: android.jdk.into_constraint(true)?, agp: android.agp.into_constraint(false)?,
            sdk_platform: android.sdk_platform.into_constraint(false)?, sdk_build_tools: android.sdk_build_tools.into_constraint(true)?,
            gradle, distribution })
    } else {
        if platform != plan::Platform::Ios { return Err(invalid()); }
        None
    };
    if [&value.xcode.version, &value.xcode.build].into_iter().any(|s| s.is_empty() || s.len() > 128
        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))) { return Err(invalid()); }
    Ok((value.sources_sha256, plan::Requirements { platform, complete: value.complete, android,
        xcode: plan::XcodePin { version: value.xcode.version, build: value.xcode.build } }))
}

#[cfg(test)]
mod tests {
    // Bounded synthetic wire DATA; not source IO or native qualification.
    use super::*;
    fn hints() -> Value {
        json!({"schemaVersion":1,"basis":"unverified-static-source-hints","sourcesSha256":"a".repeat(64),"complete":true,
            "platform":"android","projectCodeExecuted":false,"xcode":{"version":"26.3","build":"17C529"},
            "android":{"jdk":{"state":"literal","value":"17"},"agp":{"state":"literal","value":"8.9.2"},
                "sdkPlatform":{"state":"literal","value":"android-35"},"sdkBuildTools":{"state":"unspecified","value":null},
                "gradle":{"state":"literal","version":"8.14.5","distributionUrl":"https://services.gradle.org/distributions/gradle-8.14.5-bin.zip","sha256":"b".repeat(64)}}})
    }
    #[test]
    fn request_does_not_accept_tools_paths_pins_consent_or_duplicate_fields() {
        let value = json!({"schemaVersion":1,"projectId":"project-a","expectedObservationRevision":1});
        assert!(request(&serde_json::to_vec(&value).unwrap()).is_ok());
        for name in ["path", "toolState", "pins", "consent", "argv", "resume"] {
            let mut value = value.clone(); value[name] = json!("not-accepted");
            assert!(request(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(request(br#"{"schemaVersion":1,"projectId":"project-a","projectId":"project-b","expectedObservationRevision":1}"#).is_err());
    }
    #[test]
    fn hints_require_closed_nullable_fields_and_fixed_literal_wrapper_identity() {
        assert!(requirements(&serde_json::to_vec(&hints()).unwrap()).is_ok());
        for field in ["value", "state"] {
            let mut value = hints(); value["android"]["jdk"].as_object_mut().unwrap().remove(field);
            assert!(requirements(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for (field, replacement) in [("version", "8..14"), ("distributionUrl", "https://example.invalid/gradle-8.14.5-bin.zip"), ("sha256", "injected")] {
            let mut value = hints(); value["android"]["gradle"][field] = json!(replacement);
            assert!(requirements(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut missing = hints(); missing["android"]["gradle"]["sha256"] = Value::Null;
        assert!(requirements(&serde_json::to_vec(&missing).unwrap()).unwrap().1.android.unwrap().distribution.is_none());
        let mut executed = hints(); executed["projectCodeExecuted"] = json!(true);
        assert!(requirements(&serde_json::to_vec(&executed).unwrap()).is_err());
    }
    #[test]
    fn manual_xcode_wire_never_claims_installed_or_execution_authority() {
        let plan = plan::Plan { context: plan::Context { project_id:"project-a".into(),session_id:"session-a".into(),observation_revision:1,
                saved_config_sha256:"a".repeat(64),requirements_sha256:"b".repeat(64),host:plan::Host::MacArm64 },
            stamp:plan::Stamp::default(),platform:plan::Platform::Ios,state:plan::State::NeedsCheck,action:plan::Action::InspectXcodeCopy,
            reason:plan::Reason::XcodeNeedsNativeCheck,reusable:vec![],unselected_sources:vec![],policy:None,
            xcode:plan::XcodePin {version:"26.3".into(),build:"17C529".into()} };
        let value = view(&plan);
        assert_eq!(value["assurance"],json!({"writesPerformed":false,"projectCodeExecuted":false,"downloadsPlanned":0,"executionAuthorized":false,"releaseReadiness":"not-assessed"}));
        assert_eq!(value["state"],"needs-check"); assert!(value.get("path").is_none());
    }
}
pub(crate) fn host(value: plan::Host) -> &'static str {
    match value { plan::Host::MacArm64 => "macos-arm64", plan::Host::MacX64 => "macos-x86_64", plan::Host::LinuxX64 => "linux-x86_64", plan::Host::Other => "unsupported" }
}
pub(crate) fn context(value: &plan::Context) -> Value {
    json!({"projectId":value.project_id,"sessionId":value.session_id,"observationRevision":value.observation_revision,
        "savedConfigSha256":value.saved_config_sha256,"requirementsSha256":value.requirements_sha256,"host":host(value.host)})
}
pub(crate) fn stamp(value: plan::Stamp) -> Value {
    json!({"catalogGeneration":value.catalog_generation,"catalogRevision":value.catalog_revision,"sourceGeneration":value.source_generation,
        "sourceRevision":value.source_revision,"registrationGeneration":value.registration_generation,"registrationRevision":value.registration_revision,
        "serviceGeneration":value.service_generation,"serviceRevision":value.service_revision,"diagnosticsRevision":value.diagnostics_revision})
}
fn role(value: plan::Role) -> &'static str { match value { plan::Role::Jdk => "jdk", plan::Role::Sdk => "sdk", plan::Role::Gradle => "gradle" } }
pub(crate) fn view(value: &plan::Plan) -> Value {
    use plan::{Action as A, Reason as R, State as S};
    let state = match value.state { S::NeedsCheck => "needs-check", S::NeedsReview => "needs-review", S::CanReuse => "can-reuse",
        S::NeedsPreparation => "needs-preparation", S::RecoveryRequired => "recovery-required", S::Busy => "busy", S::Unsupported => "unsupported" };
    let action = match value.action {
        A::CheckProjectRequirements => "check-project-requirements", A::RefreshRegisteredTools => "refresh-registered-tools",
        A::ChooseRegisteredCopy => "choose-registered-copy", A::UseSelectedCopy => "use-selected-copy", A::ChooseJdk => "choose-jdk",
        A::ChooseSdk => "choose-sdk", A::ChooseGradle => "choose-gradle", A::InspectSources => "inspect-sources",
        A::ReviewProtectedCopy => "review-protected-copy", A::ReviewSourceProblem => "review-source-problem",
        A::CheckToolService => "check-tool-service", A::RegisterToolService => "register-tool-service",
        A::OpenToolServiceSettings => "open-tool-service-settings", A::ReconcileSetup => "reconcile-setup", A::WaitForSetup => "wait-for-setup",
        A::CheckXcode => "check-xcode", A::InstallXcodeManually => "install-xcode-manually", A::InspectXcodeCopy => "inspect-xcode-copy", A::UnsupportedHost => "unsupported-host",
    };
    let reason = match value.reason {
        R::NotChecked => "not-checked", R::RequirementsUnknown => "requirements-unknown", R::PolicyMismatch => "policy-mismatch",
        R::ExistingSelected => "existing-selected", R::ExistingUnselected => "existing-unselected", R::ExistingSources => "existing-sources",
        R::SelectionMissing => "selection-missing", R::SourceProblem => "source-problem", R::ServiceRequired => "service-required",
        R::OriginalUnsettled => "original-unsettled", R::OriginalBusy => "original-busy", R::HostUnavailable => "host-unavailable",
        R::XcodeMissing => "xcode-missing", R::XcodeMismatch => "xcode-mismatch", R::XcodeNeedsNativeCheck => "xcode-needs-native-check",
    };
    let reusable: Vec<Value> = value.reusable.iter().map(|copy| json!({"schemaVersion":1,"catalogGeneration":value.stamp.catalog_generation,
        "instance":copy.instance,"recordSha256":copy.record_sha256,"inventorySha256":copy.inventory_sha256,"osProviderSha256":copy.os_provider_sha256})).collect();
    let policy = value.policy.as_ref().map(|p| json!({"host":host(p.host),"jdkVendor":p.versions.jdk_vendor,"jdk":p.versions.jdk,
        "gradle":p.versions.gradle,"agp":p.versions.agp,"sdkPlatform":p.versions.sdk_platform,"sdkBuildTools":p.versions.sdk_build_tools,
        "distributionUrl":p.distribution.url,"distributionSha256":p.distribution.sha256}));
    json!({"schemaVersion":1,"basis":"tool-preparation-guidance","context":context(&value.context),"stamp":stamp(value.stamp),
        "platform":match value.platform {plan::Platform::Android=>"android",plan::Platform::Ios=>"ios"},"state":state,"action":action,"reason":reason,
        "reusable":reusable,"unselectedSources":value.unselected_sources.iter().map(|r|role(*r)).collect::<Vec<_>>(),"policy":policy,
        "xcode":{"version":value.xcode.version,"build":value.xcode.build},
        "assurance":{"writesPerformed":false,"projectCodeExecuted":false,"downloadsPlanned":0,"executionAuthorized":false,"releaseReadiness":"not-assessed"}})
}
