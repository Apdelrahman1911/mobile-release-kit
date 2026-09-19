//! One fixed passive saved-version/pair query. Paths arrive only from the native
//! project registry; byte comparisons are neither file authority nor build consent.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{error::BridgeError, github_workflow_edit_protocol::value_bounds, protocol::valid_id};

pub(crate) const PARAMS_LIMIT: usize = 8 * 1024;
pub(crate) const RESULT_LIMIT: usize = 4 * 1024; // DTO, not the finite RPC frame.
const CORE_ERRORS: [(&str, &str); 13] = [
    ("release_version_invalid_params", "Release-version input has an unsupported shape or size."),
    ("release_version_unavailable", "Saved release-version observation is unavailable on this platform."),
    ("release_version_config_missing", "Save the project configuration before reading the release version."),
    ("release_version_config_invalid", "The saved configuration is invalid; correct it before reading the release version."),
    ("release_version_source_missing", "The saved configuration's version file was not found."),
    ("release_version_source_invalid", "The version file does not satisfy the saved release-version policy."),
    ("release_version_unsafe", "The saved configuration or version path cannot be read safely."),
    ("release_version_changed", "The saved configuration or version source changed during observation."),
    ("release_version_unreadable", "The saved configuration or version source could not be read."),
    ("release_version_limit", "The release-version observation exceeded a supported input or observation limit."),
    ("release_version_encoding", "The saved configuration or version source is not valid UTF-8."),
    ("release_version_sensitive", "The saved configuration or version source may contain secret material; no values were returned."),
    ("release_version_cleanup_unknown", "Original release-version observation cleanup could not be confirmed."),
];

fn invalid() -> BridgeError { BridgeError::new(CORE_ERRORS[0].0, CORE_ERRORS[0].1) }

/// Discard all incoming messages, even for recognized codes.
pub(crate) fn public_error(error: BridgeError) -> BridgeError {
    if let Some((code, message)) = CORE_ERRORS.iter().find(|(code, _)| *code == error.code.as_str()) {
        return BridgeError::new(code, message);
    }
    match error.code.as_str() {
        "invalid_request" => invalid(),
        "runtime_unavailable" => BridgeError::unavailable("The admitted desktop runtime is unavailable. Installed engine launch remains disabled; no system-Python fallback is used."),
        "unknown_project" => BridgeError::new("unknown_project", "Select this project through the native folder picker before reading its saved version."),
        "busy" => BridgeError::new("busy", "The passive query slots are busy. Wait for the original queries to settle before reading again."),
        "quit_pending" => BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before reading the saved version."),
        "environment_diagnostics_busy" => BridgeError::new("environment_diagnostics_busy", "Wait for the original environment diagnostics to settle before reading the saved version."),
        "unavailable" => BridgeError::new("unavailable", "The passive observation service is unavailable; no saved version was read."),
        "shutting_down" => BridgeError::shutdown(),
        "query_timeout" => BridgeError::timeout(),
        "cleanup_unknown" => BridgeError::cleanup_unknown(),
        "output_limit" => BridgeError::new(CORE_ERRORS[9].0, CORE_ERRORS[9].1),
        "io_error" | "engine_failed" => BridgeError::new(CORE_ERRORS[8].0, CORE_ERRORS[8].1),
        _ => BridgeError::protocol(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request { pub(crate) project_id: String }

pub(crate) fn request(body: &Value) -> Result<Request, BridgeError> {
    value_bounds(body, 2, PARAMS_LIMIT).map_err(|_| invalid())?;
    let request = Request::deserialize(body).map_err(|_| invalid())?;
    if !valid_id(&request.project_id) { return Err(invalid()); }
    Ok(request)
}

/// Called only with the Rust registry result. Never lossy-normalize a path.
pub(crate) fn params(root: &Path) -> Result<Value, BridgeError> {
    let root = root.to_str().ok_or_else(invalid)?;
    let params = json!({"root": root});
    value_bounds(&params, 2, PARAMS_LIMIT).map_err(|_| invalid())?;
    Ok(params)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Version { name: String, build: u32 }

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContentComparison { bytes: u32, sha256: String }
impl ContentComparison {
    fn valid(&self, maximum: u32) -> bool {
        (1..=maximum).contains(&self.bytes) && self.sha256.len() == 64
            && self.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assurance {
    basis: String, project_code_executed: bool, tools_probed: bool, credentials_read: bool,
    git_observed: bool, store_contacted: bool, writes_performed: bool, release_readiness: String,
}
impl Assurance {
    fn valid(&self) -> bool {
        self.basis == "static-text" && !self.project_code_executed && !self.tools_probed && !self.credentials_read
            && !self.git_observed && !self.store_contacted && !self.writes_performed && self.release_readiness == "unknown"
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    schema_version: u32, source: String, version: Version, observation_scope: String, assurance: Assurance,
    saved_config: ContentComparison, saved_version: ContentComparison,
}

fn relative_display_path(path: &str) -> bool {
    // Transport/display checks only. The core owns private-tree, Unicode
    // normalization, original-object admission and saved-config selection.
    if path.is_empty() || path.len() > 512 { return false; }
    let mut count = 0;
    for part in path.split('/') {
        count += 1;
        if count > 12 || part.is_empty() || part.len() > 255 || part.starts_with('.') || part.ends_with(['.', ' '])
            || part.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || "\\:<>\"|?*".contains(c)) { return false; }
        let lower = part.to_lowercase();
        if ["private", "secrets", "credentials", "review", "testflight", "build", "deriveddata", "pods", "node_modules", "venv", "dist", "target", "__pycache__"].contains(&lower.as_str()) { return false; }
        let stem = lower.split('.').next().unwrap_or("");
        if ["con", "prn", "aux", "nul"].contains(&stem)
            || stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) && stem.as_bytes()[3].is_ascii_digit() { return false; }
    }
    true
}

pub(crate) fn result(value: Value) -> Result<Observation, BridgeError> {
    value_bounds(&value, 4, RESULT_LIMIT).map_err(|_| BridgeError::protocol())?;
    let result = Observation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    // Wire bounds, not a second marketing/iOS version policy.
    if result.schema_version != 2 || !relative_display_path(&result.source)
        || result.version.name.is_empty() || result.version.name.len() > 64
        || !result.version.name.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        || !(1..=2_100_000_000).contains(&result.version.build)
        || !result.saved_config.valid(512 * 1024) || !result.saved_version.valid(64 * 1024)
        || result.observation_scope != "single-request-non-atomic" || !result.assurance.valid() {
        return Err(BridgeError::protocol());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation() -> Value {
        json!({"schemaVersion":2,"source":"release/version.properties","version":{"name":"1.2.3","build":42},
            "savedConfig":{"bytes":1024,"sha256":"a".repeat(64)},"savedVersion":{"bytes":35,"sha256":"b".repeat(64)},
            "observationScope":"single-request-non-atomic","assurance":{"basis":"static-text","projectCodeExecuted":false,
            "toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"}})
    }
    #[test]
    fn only_registered_project_id_enters_the_command() {
        assert_eq!(request(&json!({"projectId":"project-1"})).unwrap().project_id, "project-1");
        for value in [Value::Null, json!([]), json!({}), json!({"projectId":true}), json!({"projectId":""}),
            json!({"projectId":"project/1"}), json!({"projectId":"x".repeat(65)})] {
            assert!(request(&value).is_err());
        }
        for key in ["root", "source", "configPath", "nameKey", "buildKey", "platform", "draft", "force"] {
            let mut value = json!({"projectId":"project-1"}); value[key] = json!("not-authority");
            assert!(request(&value).is_err());
        }
        assert_eq!(params(Path::new("/registered/project")).unwrap(), json!({"root":"/registered/project"}));
        assert!(params(Path::new(&"x".repeat(PARAMS_LIMIT))).is_err());
    }
    #[test]
    fn result_is_closed_bounded_and_never_release_authority() {
        let value = observation();
        assert_eq!(serde_json::to_value(result(value.clone()).unwrap()).unwrap(), value);
        for (key, bad) in [("schemaVersion", json!(true)), ("schemaVersion", json!(1)), ("schemaVersion", json!(3)), ("schemaVersion", json!("2")),
            ("observationScope", json!("atomic")), ("source", json!("../private")),
            ("source", json!("release/.env")), ("source", json!("release/version.properties.")),
            ("source", json!("release/COM1.properties")), ("source", json!("x".repeat(513)))] {
            let mut changed = value.clone(); changed[key] = bad; assert!(result(changed).is_err());
        }
        for build in [json!(true), json!(0), json!(-1), json!(1.0), json!(2_100_000_001u64), json!("42")] {
            let mut changed = value.clone(); changed["version"]["build"] = build; assert!(result(changed).is_err());
        }
        for name in [String::new(), "private\nvalue".into(), "é".into(), "1".repeat(65)] {
            let mut changed = value.clone(); changed["version"]["name"] = json!(name); assert!(result(changed).is_err());
        }
        for key in ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"] {
            let mut changed = value.clone(); changed["assurance"][key] = json!(true); assert!(result(changed).is_err());
        }
        for key in ["basis", "releaseReadiness"] {
            let mut changed = value.clone(); changed["assurance"][key] = json!("verified"); assert!(result(changed).is_err());
        }
        for location in ["", "version", "assurance", "savedConfig", "savedVersion"] {
            let mut changed = value.clone();
            if location.is_empty() { changed["unexpected"] = json!(null); } else { changed[location]["unexpected"] = json!(null); }
            assert!(result(changed).is_err());
        }
        let mut oversized = value.clone(); oversized["unexpected"] = json!("x".repeat(RESULT_LIMIT));
        assert!(result(oversized).is_err());
        // A safe suffix is wire data; iOS/platform-specific acceptance is core-owned.
        let mut suffix = value; suffix["version"]["name"] = json!("1.2.3-beta+4");
        assert!(result(suffix).is_ok());
    }
    #[test]
    fn pair_requires_both_exact_bounded_comparisons_without_v1_conversion() {
        let value = observation();
        let mut legacy = value.clone();
        legacy["schemaVersion"] = json!(1);
        legacy.as_object_mut().unwrap().remove("savedConfig");
        legacy.as_object_mut().unwrap().remove("savedVersion");
        assert!(result(legacy).is_err());
        for (field, maximum) in [("savedConfig", 512 * 1024u32), ("savedVersion", 64 * 1024u32)] {
            for bytes in [1, maximum] {
                let mut changed = value.clone(); changed[field]["bytes"] = json!(bytes);
                assert!(result(changed).is_ok());
            }
            for bytes in [json!(true), json!(0), json!(-1), json!(1.0), json!(maximum + 1), json!("35"), Value::Null] {
                let mut changed = value.clone(); changed[field]["bytes"] = bytes;
                assert!(result(changed).is_err());
            }
            for digest in [json!(""), json!("a".repeat(63)), json!("a".repeat(65)), json!("A".repeat(64)),
                json!("g".repeat(64)), json!(format!("{}\n", "a".repeat(63))), json!("é".repeat(32)), json!(true), Value::Null] {
                let mut changed = value.clone(); changed[field]["sha256"] = digest;
                assert!(result(changed).is_err());
            }
            for malformed in [Value::Null, json!([]), json!({"bytes":35}), json!({"sha256":"a".repeat(64)})] {
                let mut changed = value.clone(); changed[field] = malformed;
                assert!(result(changed).is_err());
            }
            let mut missing = value.clone(); missing.as_object_mut().unwrap().remove(field);
            assert!(result(missing).is_err());
        }
        // Shape-valid hashes are comparison DATA; this parser cannot authenticate
        // files, bind two later observations, grant consent or assert finality.
        let mut different = value.clone(); different["savedVersion"]["sha256"] = json!("c".repeat(64));
        let admitted = result(different.clone()).unwrap();
        assert_eq!(serde_json::to_value(admitted).unwrap(), different);
        assert_eq!(different["assurance"], value["assurance"]);
    }
    #[test]
    fn fixed_errors_do_not_relay_messages_or_unknown_codes() {
        for (code, message) in CORE_ERRORS {
            assert_eq!(public_error(BridgeError::new(code, "private-input")), BridgeError::new(code, message));
        }
        for code in ["runtime_unavailable", "unknown_project", "busy", "quit_pending", "environment_diagnostics_busy", "unavailable",
            "shutting_down", "query_timeout", "cleanup_unknown"] {
            let error = public_error(BridgeError::new(code, "private-input"));
            assert_eq!(error.code, code); assert!(!error.message.contains("private-input")); assert!(!error.retryable);
        }
        for code in ["release_version_invented", "unexpected-private-code", "protocol_error"] {
            assert_eq!(public_error(BridgeError::new(code, "private-input")), BridgeError::protocol());
        }
    }
    #[test]
    fn dto_limit_does_not_replace_passive_framing_limits() {
        assert!(PARAMS_LIMIT < crate::protocol::REQUEST_LIMIT);
        assert!(RESULT_LIMIT < crate::protocol::RESPONSE_LIMIT);
        let bytes = crate::protocol::encode_request("query-1", crate::protocol::Method::ReleaseVersionObserve,
            &json!({"root":"/registered/project"})).unwrap();
        let frame = crate::protocol::strict_json(&bytes).unwrap();
        assert_eq!(frame["method"], "release.version.observe");
        assert_eq!(frame["params"], json!({"root":"/registered/project"}));
    }
}
