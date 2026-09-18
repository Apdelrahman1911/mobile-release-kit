//! Passive toolchain requirements, not tool discovery or permission to execute.
//! The core owns configuration and version policy. These closed DTOs preserve
//! its unknown observations and bind a result to the actual request context.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{edit_protocol::bounded, error::BridgeError, protocol::check_value};

pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
const DRAFT_LIMIT: usize = 512 * 1024;
const REQUEST_INVALID: (&str, &str) = ("environment_request_invalid", "The environment request is invalid.");
const DRAFT_INVALID: (&str, &str) = ("environment_draft_invalid", "Review the project configuration before loading environment requirements.");
const UNAVAILABLE: (&str, &str) = ("environment_unavailable", "Environment requirements could not be loaded. Check the core connection and try again.");

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { Build, ArtifactValidation }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context { pub platform: Platform, pub operation: Operation }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request { draft: Value, platform: Platform, operation: Operation }
impl Request {
    pub(crate) fn context(&self) -> Context { Context { platform: self.platform, operation: self.operation } }
    pub(crate) fn into_params(self) -> Result<Value, BridgeError> {
        serde_json::to_value(self).map_err(|_| invalid_request())
    }
}
fn invalid_request() -> BridgeError { BridgeError::new(REQUEST_INVALID.0, REQUEST_INVALID.1) }
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn request(body: &Value) -> Result<Request, BridgeError> {
    if !keys(body, &["draft", "platform", "operation"]) { return Err(invalid_request()); }
    check_value(body).map_err(|_| invalid_request())?;
    bounded(body, crate::protocol::REQUEST_LIMIT - 1).map_err(|_| invalid_request())?;
    let request = Request::deserialize(body).map_err(|_| invalid_request())?;
    if !request.draft.is_object() { return Err(invalid_request()); }
    bounded(&request.draft, DRAFT_LIMIT).map_err(|_| invalid_request())?;
    // Deliberately no Rust config validator, PATH lookup, root or executable.
    Ok(request)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum HostPlatform { Linux, Macos, Windows, Other }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum State { RequirementsOnly, PlatformDisabled }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Role {
    AndroidJdk, AndroidGradleWrapper, AndroidSdk, AndroidBundletool,
    AppleMacos, AppleXcode, AppleSigningTools, AppleCodesign, AppleOpenssl, AppleSecurityFramework,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Kind { ExternalToolchain, ProjectFile, BundledHelper, NativeOs }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum BaselineKind { ExactPin, WorkflowReference, ProjectDefined, PlatformDefined, None }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Requiredness { Required, Optional, Conditional }

impl Context {
    fn roles(self) -> &'static [Role] {
        use Role::*;
        match (self.platform, self.operation) {
            (Platform::Android, Operation::Build) => &[AndroidJdk, AndroidGradleWrapper, AndroidSdk],
            (Platform::Android, Operation::ArtifactValidation) => &[AndroidJdk, AndroidBundletool],
            (Platform::Ios, Operation::Build) => &[AppleMacos, AppleXcode, AppleSigningTools],
            (Platform::Ios, Operation::ArtifactValidation) => &[AppleMacos, AppleCodesign, AppleOpenssl, AppleSecurityFramework],
        }
    }
}
impl Role {
    fn kind(self) -> Kind {
        match self {
            Self::AndroidGradleWrapper => Kind::ProjectFile,
            Self::AndroidBundletool => Kind::BundledHelper,
            Self::AppleMacos | Self::AppleSigningTools | Self::AppleCodesign | Self::AppleOpenssl | Self::AppleSecurityFramework => Kind::NativeOs,
            _ => Kind::ExternalToolchain,
        }
    }
}
fn text(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty()) && value.len() <= max
        && !value.chars().any(|ch| ch <= '\u{1f}' || ch == '\u{7f}')
}
fn optional_text(value: &Option<String>) -> bool { value.as_deref().is_some_and(|value| text(value, 128, false)) }
fn sha256(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Baseline {
    kind: BaselineKind, version: Option<String>, build: Option<String>, sha256: Option<String>, max_bytes: Option<u64>,
}
impl Baseline {
    fn valid(&self, role: Role) -> bool {
        // Validate the descriptive wire shape, not a duplicated version pin.
        // The expected version/digest values remain the core's single policy.
        let no_file = self.sha256.is_none() && self.max_bytes.is_none();
        match role {
            Role::AndroidJdk => self.kind == BaselineKind::WorkflowReference && optional_text(&self.version)
                && self.build.is_none() && no_file,
            Role::AndroidBundletool => self.kind == BaselineKind::ExactPin && optional_text(&self.version)
                && self.build.is_none() && sha256(&self.sha256)
                && self.max_bytes.is_some_and(|size| (1..=9_007_199_254_740_991).contains(&size)),
            Role::AppleXcode => self.kind == BaselineKind::ExactPin && optional_text(&self.version)
                && optional_text(&self.build) && no_file,
            Role::AndroidGradleWrapper | Role::AndroidSdk => self.kind == BaselineKind::ProjectDefined
                && self.version.is_none() && self.build.is_none() && no_file,
            _ => self.kind == BaselineKind::PlatformDefined && self.version.is_none() && self.build.is_none() && no_file,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Help {
    label: String, requiredness: Requiredness, required_when: String,
    what: String, why: String, r#where: String, format: String, failure: String,
}
impl Help {
    fn valid(&self) -> bool {
        [&self.label, &self.what, &self.why, &self.r#where, &self.format, &self.failure]
            .iter().all(|value| text(value, 1024, false))
            && text(&self.required_when, 1024, self.requiredness != Requiredness::Conditional)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorHelp { platform: Help, operation: Help }
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Requirement {
    id: Role, kind: Kind, presence: String, version_state: String, inspection: String,
    baseline: Baseline, help: Help,
}
impl Requirement {
    fn valid(&self, role: Role) -> bool {
        self.id == role && self.kind == role.kind() && self.presence == "unknown"
            && self.version_state == "unknown" && self.inspection == "not-run"
            && self.baseline.valid(role) && self.help.valid()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assurance {
    basis: String, project_code_executed: bool, tools_probed: bool, credentials_read: bool,
    git_observed: bool, store_contacted: bool, writes_performed: bool, release_readiness: String,
}
impl Assurance {
    fn valid(&self) -> bool {
        self.basis == "schema-policy" && !self.project_code_executed && !self.tools_probed && !self.credentials_read
            && !self.git_observed && !self.store_contacted && !self.writes_performed && self.release_readiness == "unknown"
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Requirements {
    schema_version: u32, policy_version: String, host_platform: HostPlatform, context: Context,
    platform_enabled: bool, state: State, coverage: String, native_inspection: String,
    dependency_completeness: String, requirements: Vec<Requirement>, help: SelectorHelp,
    limitations: Vec<String>, assurance: Assurance,
}
pub(crate) fn result(value: Value, context: Context) -> Result<Requirements, BridgeError> {
    check_value(&value).map_err(|_| BridgeError::protocol())?;
    bounded(&value, RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
    // Serde Option alone would also accept omitted fields. The baseline's null
    // members are explicit required DATA, not defaults or observed values.
    let rows = value.get("requirements").and_then(Value::as_array).ok_or_else(BridgeError::protocol)?;
    if rows.len() > 4 || rows.iter().any(|row| !row.get("baseline").is_some_and(|baseline|
        keys(baseline, &["kind", "version", "build", "sha256", "maxBytes"]))) { return Err(BridgeError::protocol()); }
    let result = Requirements::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    let expected = if result.platform_enabled { context.roles() } else { &[] };
    let expected_state = if result.platform_enabled { State::RequirementsOnly } else { State::PlatformDisabled };
    if result.schema_version != 1 || result.policy_version != "environment-requirements-v1" || result.context != context
        || result.state != expected_state
        || result.coverage != "toolchain-prerequisites-only" || result.native_inspection != "unavailable"
        || result.dependency_completeness != "unknown" || !result.assurance.valid()
        || result.requirements.len() != expected.len()
        || !result.requirements.iter().zip(expected).all(|(row, role)| row.valid(*role))
        || !result.help.platform.valid() || !result.help.operation.valid()
        || result.limitations.is_empty() || result.limitations.len() > 8
        || !result.limitations.iter().all(|value| text(value, 1024, false)) { return Err(BridgeError::protocol()); }
    Ok(result)
}

pub(crate) fn decode_envelope(bytes: &[u8], id: &str) -> Result<Value, BridgeError> {
    // Includes the complete envelope and its newline, not just result JSON.
    if bytes.len() > RESPONSE_LIMIT { return Err(BridgeError::protocol()); }
    crate::protocol::decode_response(bytes, id).map_err(|error| {
        if !error.retryable && [REQUEST_INVALID, DRAFT_INVALID, UNAVAILABLE].iter().any(|(code, message)| error.code == *code && error.message == *message) {
            error
        } else { BridgeError::protocol() }
    })
}
pub(crate) fn public_error(error: BridgeError) -> BridgeError {
    // Never expose a core exception, input value or launch-path diagnostic.
    match error.code.as_str() {
        "environment_request_invalid" | "invalid_request" => invalid_request(),
        "environment_draft_invalid" => BridgeError::new(DRAFT_INVALID.0, DRAFT_INVALID.1),
        "protocol_error" => BridgeError::protocol(),
        "query_timeout" => BridgeError::timeout(),
        "cleanup_unknown" => BridgeError::cleanup_unknown(),
        "shutting_down" => BridgeError::shutdown(),
        _ => BridgeError::new(UNAVAILABLE.0, UNAVAILABLE.1),
    }
}

#[cfg(test)]
mod tests {
    // In-memory wire contracts only. No runtime, filesystem or tool execution.
    use super::*;
    use serde_json::json;

    fn help() -> Value {
        json!({"label":"Toolchain", "requiredness":"required", "requiredWhen":"For this operation",
            "what":"Expected prerequisite", "why":"Required by the selected core operation", "where":"Tool vendor",
            "format":"A project-compatible installation", "failure":"The native operation may not be available"})
    }
    fn fixture(context: Context) -> Value {
        let rows = match (context.platform, context.operation) {
            (Platform::Android, Operation::Build) => vec![
                ("android-jdk", "external-toolchain", "workflow-reference", json!("21"), Value::Null, Value::Null, Value::Null),
                ("android-gradle-wrapper", "project-file", "project-defined", Value::Null, Value::Null, Value::Null, Value::Null),
                ("android-sdk", "external-toolchain", "project-defined", Value::Null, Value::Null, Value::Null, Value::Null)],
            (Platform::Android, Operation::ArtifactValidation) => vec![
                ("android-jdk", "external-toolchain", "workflow-reference", json!("21"), Value::Null, Value::Null, Value::Null),
                ("android-bundletool", "bundled-helper", "exact-pin", json!("1.18.3"), Value::Null, json!("a".repeat(64)), json!(32520401))],
            (Platform::Ios, Operation::Build) => vec![
                ("apple-macos", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null),
                ("apple-xcode", "external-toolchain", "exact-pin", json!("26.3"), json!("17C529"), Value::Null, Value::Null),
                ("apple-signing-tools", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null)],
            (Platform::Ios, Operation::ArtifactValidation) => vec![
                ("apple-macos", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null),
                ("apple-codesign", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null),
                ("apple-openssl", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null),
                ("apple-security-framework", "native-os", "platform-defined", Value::Null, Value::Null, Value::Null, Value::Null)],
        };
        json!({"schemaVersion":1, "policyVersion":"environment-requirements-v1", "hostPlatform":"linux", "context":context,
            "platformEnabled":true, "state":"requirements-only", "coverage":"toolchain-prerequisites-only",
            "nativeInspection":"unavailable", "dependencyCompleteness":"unknown",
            "requirements":rows.into_iter().map(|(id,kind,baseline,version,build,sha256,max_bytes)|
                json!({"id":id,"kind":kind,"presence":"unknown","versionState":"unknown","inspection":"not-run",
                    "baseline":{"kind":baseline,"version":version,"build":build,"sha256":sha256,"maxBytes":max_bytes},"help":help()})).collect::<Vec<_>>(),
            "help":{"platform":help(), "operation":help()}, "limitations":["No native checks have run."],
            "assurance":{"basis":"schema-policy", "projectCodeExecuted":false, "toolsProbed":false, "credentialsRead":false,
                "gitObserved":false, "storeContacted":false, "writesPerformed":false, "releaseReadiness":"unknown"}})
    }
    fn context() -> Context { Context { platform: Platform::Android, operation: Operation::Build } }
    fn envelope(value: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.push(b'\n'); bytes
    }
    #[test]
    fn requests_are_closed_bounded_and_leave_configuration_policy_in_core() {
        let original = json!({"draft":{"unknownPolicyKey":"core decides"},"platform":"android","operation":"build"});
        assert_eq!(request(&original).and_then(Request::into_params).unwrap(), original);
        for (key, value) in [("platform",json!("linux")),("operation",json!("execute")),("draft",json!([])),("root",json!("private"))] {
            let mut bad = original.clone(); bad[key] = value;
            assert_eq!(request(&bad).err().unwrap().code, "environment_request_invalid");
        }
        let mut bad = original.clone(); bad["draft"] = json!({"tooLarge":"x".repeat(DRAFT_LIMIT)});
        assert!(request(&bad).is_err());
        let mut deep = Value::Null; for _ in 0..32 { deep = json!({"node":deep}); }
        bad["draft"] = deep; assert!(request(&bad).is_err());
        for key in ["draft","platform","operation"] {
            let mut bad = original.clone(); bad.as_object_mut().unwrap().remove(key); assert!(request(&bad).is_err());
        }
    }
    #[test]
    fn context_roles_and_disabled_platforms_are_exact() {
        for platform in [Platform::Android, Platform::Ios] {
            for operation in [Operation::Build, Operation::ArtifactValidation] {
                let context = Context { platform, operation }; let original = fixture(context);
                assert!(result(original.clone(), context).is_ok());
                let other = Context { platform, operation: if operation == Operation::Build { Operation::ArtifactValidation } else { Operation::Build } };
                assert!(result(original.clone(), other).is_err());
                let mut bad = original.clone(); bad["requirements"].as_array_mut().unwrap().swap(0,1); assert!(result(bad, context).is_err());
                let mut bad = original.clone(); bad["requirements"][1] = bad["requirements"][0].clone(); assert!(result(bad, context).is_err());
                let mut disabled = original; disabled["platformEnabled"] = json!(false); disabled["state"] = json!("platform-disabled");
                assert!(result(disabled.clone(), context).is_err()); disabled["requirements"] = json!([]);
                assert!(result(disabled.clone(), context).is_ok()); disabled["state"] = json!("requirements-only"); assert!(result(disabled, context).is_err());
            }
        }
    }
    #[test]
    fn results_cannot_claim_observation_or_extra_authority() {
        let original = fixture(context());
        for key in ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"] {
            let mut bad = original.clone(); bad["assurance"][key] = json!(true); assert!(result(bad, context()).is_err());
        }
        for (key, value) in [("presence","present"),("versionState","verified"),("inspection","passed"),("kind","bundled-helper"),("observedVersion","21")] {
            let mut bad = original.clone(); bad["requirements"][0][key] = json!(value); assert!(result(bad, context()).is_err());
        }
        for (key, value) in [("state","ready"),("nativeInspection","complete"),("dependencyCompleteness","known"),("hostPlatform","darwin")] {
            let mut bad = original.clone(); bad[key] = json!(value); assert!(result(bad, context()).is_err());
        }
        let mut bad = original; bad["assurance"]["releaseReadiness"] = json!("ready"); assert!(result(bad, context()).is_err());
    }
    #[test]
    fn baseline_nulls_and_help_are_explicit_not_implicit_defaults() {
        let original = fixture(context());
        for key in ["version", "build", "sha256", "maxBytes"] {
            let mut bad = original.clone(); bad["requirements"][0]["baseline"].as_object_mut().unwrap().remove(key);
            assert!(result(bad, context()).is_err());
        }
        for value in [json!(true),json!("not-a-pin")] {
            let mut bad = original.clone(); bad["requirements"][0]["baseline"]["maxBytes"] = value; assert!(result(bad, context()).is_err());
        }
        let mut bad = original.clone(); bad["help"]["platform"]["what"] = json!("é".repeat(513)); assert!(result(bad, context()).is_err());
        let mut bad = original.clone(); bad["requirements"][0]["help"]["requiredness"] = json!("conditional");
        bad["requirements"][0]["help"]["requiredWhen"] = json!(""); assert!(result(bad, context()).is_err());
        let mut bad = original; bad["help"]["operation"].as_object_mut().unwrap().remove("where"); assert!(result(bad, context()).is_err());
    }
    #[test]
    fn method_envelope_bound_includes_framing_and_errors_never_echo_inputs() {
        let wrap = |payload: Value| envelope(json!({"protocol":1,"id":"query-1","ok":true,"result":payload}));
        let overhead = wrap(json!({"padding":""})).len();
        let exact = wrap(json!({"padding":"x".repeat(RESPONSE_LIMIT-overhead)}));
        assert_eq!(exact.len(), RESPONSE_LIMIT); assert!(decode_envelope(&exact,"query-1").is_ok());
        assert!(decode_envelope(&wrap(json!({"padding":"x".repeat(RESPONSE_LIMIT-overhead+1)})),"query-1").is_err());
        assert!(decode_envelope(&exact,"other").is_err());
        for (code, message) in [REQUEST_INVALID,DRAFT_INVALID,UNAVAILABLE] {
            let bytes = envelope(json!({"protocol":1,"id":"query-1","ok":false,"error":{"code":code,"message":message,"retryable":false}}));
            assert_eq!(decode_envelope(&bytes,"query-1").unwrap_err().message, message);
        }
        let bytes = envelope(json!({"protocol":1,"id":"query-1","ok":false,"error":{"code":"environment_draft_invalid","message":"PRIVATE-SENTINEL","retryable":false}}));
        assert_eq!(decode_envelope(&bytes,"query-1").unwrap_err(), BridgeError::protocol());
        for code in ["runtime_unavailable", "unknown_exception", "environment_draft_invalid"] {
            assert!(!public_error(BridgeError::new(code,"PRIVATE-SENTINEL")).message.contains("PRIVATE-SENTINEL"));
        }
    }
}
