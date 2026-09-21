//! A closed documents-only observation. Neither declared hashes nor a consistent
//! chain authenticate a workflow, inspect payload bytes, or authorize a release.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, error::BridgeError, github_workflow_edit_protocol::value_bounds};

pub(crate) const RESULT_LIMIT: usize = 64 * 1024;
pub(crate) const NODE_LIMIT: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Problem { Unavailable, Busy, Cancelled, StaleSelection, UnsafeSelection, ObservationFailed, Limit, Deadline, CleanupUnknown }
pub(crate) fn refused(problem: Problem) -> BridgeError {
    let (code, message) = match problem {
        Problem::Unavailable => ("artifact_evidence_unavailable", "The evidence-folder inspector is unavailable in this build or on this platform."),
        Problem::Busy => ("artifact_evidence_busy", "Wait for the original native operation to settle before inspecting evidence."),
        Problem::Cancelled => ("artifact_evidence_cancelled", "The original evidence operation was cancelled. No result was accepted."),
        Problem::StaleSelection => ("artifact_evidence_stale_selection", "This request does not identify the current evidence selection and original operation."),
        Problem::UnsafeSelection => ("artifact_evidence_unsafe_selection", "The selected evidence folder could not be read safely."),
        Problem::ObservationFailed => ("artifact_evidence_observation_failed", "The evidence documents could not be observed. No result was accepted."),
        Problem::Limit => ("artifact_evidence_limit", "The evidence observation exceeded a supported input or output limit."),
        Problem::Deadline => ("artifact_evidence_deadline", "The evidence observation reached its deadline. Wait for its original operation to settle."),
        Problem::CleanupUnknown => ("artifact_evidence_cleanup_unknown", "Original evidence-operation cleanup is unconfirmed. Further work is disabled."),
    };
    BridgeError::new(code, message)
}
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("artifact_evidence_invalid", "The evidence request has an unsupported shape or identity.")
}
pub(crate) fn core_problem(error: &BridgeError) -> Problem {
    match error.code.as_str() {
        "artifacts_unavailable" | "runtime_unavailable" => Problem::Unavailable,
        "busy" => Problem::Busy,
        "artifacts_unsafe" => Problem::UnsafeSelection,
        "artifacts_changed" => Problem::StaleSelection,
        "artifacts_limit" | "output_limit" => Problem::Limit,
        "artifacts_deadline" | "query_timeout" => Problem::Deadline,
        "artifacts_cleanup_unknown" | "cleanup_unknown" => Problem::CleanupUnknown,
        _ => Problem::ObservationFailed,
    }
}

pub(crate) fn selection_id(value: &str) -> bool {
    value.strip_prefix("evidence-").is_some_and(|tail| !tail.is_empty() && tail.len() <= 55
        && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
}
fn decimal(value: &str, positive: bool, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" && !positive || !value.starts_with('0'))
}
pub(crate) fn operation_id(value: &str) -> Option<u32> {
    if !decimal(value, true, 10) { return None; }
    value.parse::<u32>().ok().filter(|id| *id < u32::MAX)
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| if size == 40 { b.is_ascii_hexdigit() } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
}
pub(crate) fn display_text(value: &str, characters: usize, bytes: usize) -> bool {
    !value.is_empty() && value.len() <= bytes && value.chars().count() <= characters
        // Match the core/renderer Cc/Cf/Cs boundary, not just bidi controls.
        // Rust strings cannot contain Cs. These are the Unicode Cf ranges.
        && !value.chars().any(|c| c.is_control() || matches!(c,
            '\u{00ad}' | '\u{0600}'..='\u{0605}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' |
            '\u{0890}'..='\u{0891}' | '\u{08e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' |
            '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' |
            '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' |
            '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' |
            '\u{e0001}' | '\u{e0020}'..='\u{e007f}'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub(crate) fn empty_request(value: &Value) -> Result<(), BridgeError> {
    value_bounds(value, 2, 256).map_err(|_| invalid())?;
    if !value.is_object() { return Err(invalid()); }
    Empty::deserialize(value).map(|_| ()).map_err(|_| invalid())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observe { pub(crate) selection_id: String }
pub(crate) fn observe_request(value: &Value) -> Result<Observe, BridgeError> {
    value_bounds(value, 2, 256).map_err(|_| invalid())?;
    if !value.is_object() { return Err(invalid()); }
    let input = Observe::deserialize(value).map_err(|_| invalid())?;
    if !selection_id(&input.selection_id) { return Err(invalid()); }
    Ok(input)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) selection_id: Option<String> }
pub(crate) fn cancel_request(value: &Value) -> Result<Cancel, BridgeError> {
    value_bounds(value, 2, 256).map_err(|_| invalid())?;
    // Option<T> alone would accept a missing key; the null is mandatory.
    if !value.as_object().is_some_and(|o| o.len() == 2 && o.contains_key("selectionId")) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if operation_id(&input.operation_id).is_none() || input.selection_id.as_ref().is_some_and(|id| !selection_id(id)) { return Err(invalid()); }
    Ok(input)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RootIdentity {
    pub(crate) device: String, pub(crate) inode: String,
    pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
}
/// Only called with the private evidence registry, never a renderer path.
pub(crate) fn params(root: &RegisteredRoot) -> Result<Value, BridgeError> {
    let path = root.path.to_str().ok_or_else(invalid)?;
    if path.len() > 4096 || !root.path.is_absolute() || root.path.components().count() > 129 { return Err(invalid()); }
    let value = json!({"root":path,"expectedRoot":root.identity.evidence_identity()});
    value_bounds(&value, 3, 8 * 1024).map_err(|_| invalid())?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind { Manifest, Receipt, Intent }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DocumentState { Missing, Invalid, Valid }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document { kind: Kind, state: DocumentState }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome { Consistent, Incomplete, Invalid, Inconsistent }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Version { marketing: String, build: u32 }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source { commit: String, tree: String }
const ROLES: [&str; 8] = ["android-aab", "android-mapping", "android-native-symbols", "ios-ipa", "ios-archive", "ios-dsyms", "store-metadata", "validation-report"];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact { logical_name: String, declared_bytes: String, sha256: String }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordedRun { run_id: String, attempt: String }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Runs { authorized_by: RecordedRun, executed_by: RecordedRun, produced_by: RecordedRun }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Digests { manifest: String, receipt: String, intent: String }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Summary {
    platform: String, application_id: String, version: Version, source: Source,
    artifacts: Vec<Artifact>, recorded_runs: Runs, document_payload_sha256: Digests,
}
fn marketing_format(value: &str) -> bool {
    let head = if let Some(index) = value.find(['-', '+']) {
        let suffix = &value[index + 1..];
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')) { return false; }
        &value[..index]
    } else { value };
    let parts: Vec<&str> = head.split('.').collect();
    (2..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}
impl Summary {
    fn valid(&self) -> bool {
        if !matches!(self.platform.as_str(), "android" | "ios") || !display_text(&self.application_id, 255, 1024)
            || self.application_id.chars().count() < 3 || !display_text(&self.version.marketing, 64, 256) || !marketing_format(&self.version.marketing)
            || !(1..=2_100_000_000).contains(&self.version.build)
            || !hex(&self.source.commit, 40) || !hex(&self.source.tree, 40) || self.artifacts.len() < 3 || self.artifacts.len() > 5 { return false; }
        let mut previous = None;
        for artifact in &self.artifacts {
            let Some(index) = ROLES.iter().position(|role| *role == artifact.logical_name) else { return false; };
            if previous.is_some_and(|old| old >= index) || !decimal(&artifact.declared_bytes, true, 64) || !hex(&artifact.sha256, 64) { return false; }
            previous = Some(index);
        }
        let present = |name: &str| self.artifacts.iter().any(|a| a.logical_name == name);
        if !present("store-metadata") || !present("validation-report") { return false; }
        if self.platform == "android" {
            if !present("android-aab") || self.artifacts.iter().any(|a| a.logical_name.starts_with("ios-")) { return false; }
        } else if !present("ios-ipa") || !present("ios-archive") || self.artifacts.iter().any(|a| a.logical_name.starts_with("android-")) { return false; }
        [&self.recorded_runs.authorized_by, &self.recorded_runs.executed_by, &self.recorded_runs.produced_by].into_iter()
            .all(|run| decimal(&run.run_id, true, 64) && decimal(&run.attempt, true, 64))
            && [&self.document_payload_sha256.manifest, &self.document_payload_sha256.receipt, &self.document_payload_sha256.intent].into_iter().all(|sha| hex(sha, 64))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assurance {
    level: String, documents_only: bool, artifact_bytes_verified: bool, workflow_authenticated: bool,
    store_state_observed: bool, compared_with_source_project: bool, release_ready: bool, recovery_authorized: bool,
}
impl Assurance {
    fn valid(&self) -> bool {
        self.level == "local-document-consistency" && self.documents_only && !self.artifact_bytes_verified && !self.workflow_authenticated
            && !self.store_state_observed && !self.compared_with_source_project && !self.release_ready && !self.recovery_authorized
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation { schema_version: u8, outcome: Outcome, documents: Vec<Document>, summary: Option<Summary>, assurance: Assurance }
impl Observation {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !self.assurance.valid() || self.documents.len() != 3
            || !self.documents.iter().map(|d| d.kind).eq([Kind::Manifest, Kind::Receipt, Kind::Intent]) { return false; }
        let invalid = self.documents.iter().any(|d| d.state == DocumentState::Invalid);
        let missing = self.documents.iter().any(|d| d.state == DocumentState::Missing);
        match self.outcome {
            Outcome::Invalid => invalid && self.summary.is_none(),
            Outcome::Incomplete => !invalid && missing && self.summary.is_none(),
            Outcome::Inconsistent => !invalid && !missing && self.summary.is_none(),
            Outcome::Consistent => !invalid && !missing && self.summary.as_ref().is_some_and(Summary::valid),
        }
    }
}
fn bounds(value: &Value) -> Result<(), BridgeError> {
    let mut pending = vec![(value, 1usize)]; let mut nodes = 0usize;
    while let Some((item, depth)) = pending.pop() {
        nodes += 1;
        if nodes > NODE_LIMIT || depth > 8 { return Err(BridgeError::protocol()); }
        match item {
            Value::Object(items) => {
                if nodes + pending.len() + 2 * items.len() > NODE_LIMIT { return Err(BridgeError::protocol()); }
                nodes += items.len(); pending.extend(items.values().map(|v| (v, depth + 1)));
            }
            Value::Array(items) => {
                if nodes + pending.len() + items.len() > NODE_LIMIT { return Err(BridgeError::protocol()); }
                pending.extend(items.iter().map(|v| (v, depth + 1)));
            }
            _ => {},
        }
    }
    value_bounds(value, 8, RESULT_LIMIT).map_err(|_| BridgeError::protocol())
}
pub(crate) fn result(value: Value) -> Result<Observation, BridgeError> {
    bounds(&value)?;
    // Optional fields are explicitly present in this contract, never omitted.
    if !value.as_object().is_some_and(|o| o.contains_key("summary")) { return Err(BridgeError::protocol()); }
    let result = Observation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    // Serde-derived structs can accept positional arrays. Exact round-trip
    // equality rejects every such normalization and omitted optional field.
    if !result.valid() || serde_json::to_value(&result).map_err(|_| BridgeError::protocol())? != value { return Err(BridgeError::protocol()); }
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Phase { Idle, Choosing, Selected, Observing, Observed, Stopping, Cancelled, Refused, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OperationKind { Choose, Observe }
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Selection { pub(crate) selection_id: String, pub(crate) display_name: String }
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) operation_id: String, pub(crate) kind: OperationKind, pub(crate) selection_id: Option<String> }
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u8, pub(crate) revision: String, pub(crate) availability: &'static str,
    pub(crate) phase: Phase, pub(crate) selection: Option<Selection>, pub(crate) operation: Option<Operation>,
    pub(crate) result: Option<Observation>, pub(crate) problem: Option<Problem>,
}
impl Status {
    pub(crate) fn unavailable(revision: u64) -> Self {
        Self { schema_version: 1, revision: revision.to_string(), availability: "unavailable", phase: Phase::Idle,
            selection: None, operation: None, result: None, problem: Some(Problem::Unavailable) }
    }
    pub(crate) fn checked(self) -> Result<Self, BridgeError> {
        if !self.valid() { return Err(BridgeError::protocol()); }
        let value = serde_json::to_value(&self).map_err(|_| refused(Problem::Limit))?;
        bounds(&value).map_err(|_| refused(Problem::Limit))?;
        Ok(self)
    }
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !decimal(&self.revision, false, 20) || self.revision.parse::<u64>().is_err() { return false; }
        if self.selection.as_ref().is_some_and(|s| !selection_id(&s.selection_id)
            || !display_text(&s.display_name,128,512) || s.display_name.contains(['/', '\\'])) { return false; }
        if self.operation.as_ref().is_some_and(|op| operation_id(&op.operation_id).is_none()
            || match op.kind { OperationKind::Choose => op.selection_id.is_some(), OperationKind::Observe => !op.selection_id.as_deref().is_some_and(selection_id) }) { return false; }
        if self.availability == "unavailable" {
            return self.phase == Phase::Idle && self.selection.is_none() && self.operation.is_none()
                && self.result.is_none() && self.problem == Some(Problem::Unavailable);
        }
        if self.availability != "available" || (self.phase == Phase::Unknown) != (self.problem == Some(Problem::CleanupUnknown)) { return false; }
        if self.phase == Phase::Observed {
            if !self.result.as_ref().is_some_and(Observation::valid) { return false; }
        } else if self.result.is_some() { return false; }
        match self.phase {
            Phase::Idle => self.selection.is_none() && self.operation.is_none() && self.problem.is_none(),
            Phase::Choosing => self.selection.is_none() && self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Choose),
            Phase::Selected => self.selection.is_some() && self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Choose),
            Phase::Observing | Phase::Observed => self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Observe
                && self.selection.as_ref().is_some_and(|s| op.selection_id.as_deref() == Some(s.selection_id.as_str()))),
            Phase::Stopping => self.problem.is_some() && self.operation.is_some(),
            Phase::Cancelled => self.problem == Some(Problem::Cancelled) && self.operation.is_some(),
            Phase::Refused => self.problem.is_some(),
            Phase::Unknown => self.problem == Some(Problem::CleanupUnknown),
        }
    }
}

#[cfg(test)]
pub(crate) fn assert_candidate_wire_contract() {
    // Explicit entry for the harness=false observer, reusing the existing
    // bounded wire DATA tests rather than creating another execution suite.
    tests::closed_commands_cannot_supply_paths_or_cancel_by_selection_alone_body();
    tests::observation_is_consistency_only_and_big_decimals_remain_text_body();
    tests::core_result_fixtures_round_trip_without_native_normalization_body();
    tests::positional_nested_documents_and_noncanonical_summary_shapes_are_refused_body();
    tests::failure_precedence_and_no_partial_summary_are_wire_contracts_body();
    tests::status_cleanup_unknown_and_terminal_cancellation_cannot_be_relabelled_body();
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn consistent() -> Value {
        json!({"schemaVersion":1,"outcome":"consistent","documents":[{"kind":"manifest","state":"valid"},{"kind":"receipt","state":"valid"},{"kind":"intent","state":"valid"}],
            "summary":{"platform":"android","applicationId":"example.fixture","version":{"marketing":"1.2.3","build":42},"source":{"commit":"a".repeat(40),"tree":"b".repeat(40)},
                "artifacts":[{"logicalName":"android-aab","declaredBytes":"9007199254740993","sha256":"c".repeat(64)},
                    {"logicalName":"store-metadata","declaredBytes":"12","sha256":"a".repeat(64)},
                    {"logicalName":"validation-report","declaredBytes":"34","sha256":"b".repeat(64)}],
                "recordedRuns":{"authorizedBy":{"runId":"9007199254740993","attempt":"1"},"executedBy":{"runId":"9007199254740994","attempt":"2"},"producedBy":{"runId":"9007199254740995","attempt":"3"}},
                "documentPayloadSha256":{"manifest":"d".repeat(64),"receipt":"e".repeat(64),"intent":"f".repeat(64)}},
            "assurance":{"level":"local-document-consistency","documentsOnly":true,"artifactBytesVerified":false,"workflowAuthenticated":false,"storeStateObserved":false,"comparedWithSourceProject":false,"releaseReady":false,"recoveryAuthorized":false}})
    }
    #[test]
    fn closed_commands_cannot_supply_paths_or_cancel_by_selection_alone() { closed_commands_cannot_supply_paths_or_cancel_by_selection_alone_body(); }

    pub(super) fn closed_commands_cannot_supply_paths_or_cancel_by_selection_alone_body() {
        assert!(empty_request(&json!({})).is_ok());
        assert!(observe_request(&json!({"selectionId":"evidence-abc"})).is_ok());
        assert!(cancel_request(&json!({"operationId":"42","selectionId":"evidence-abc"})).is_ok());
        assert!(cancel_request(&json!({"operationId":"43","selectionId":null})).is_ok());
        for value in [json!([]), json!(["evidence-abc"]), json!({"root":"/tmp"}), json!({"selectionId":"project-1"}), json!({"selectionId":"evidence-abc","root":"/tmp"})] {
            assert!(empty_request(&value).is_err()); assert!(observe_request(&value).is_err());
        }
        for value in [json!({"operationId":"42"}), json!({"selectionId":"evidence-abc"}), json!({"operationId":42,"selectionId":null}),
            json!({"operationId":"042","selectionId":null}), json!({"operationId":"4294967295","selectionId":null}), json!({"operationId":"0","selectionId":null})] {
            assert!(cancel_request(&value).is_err());
        }
    }
    #[test]
    fn observation_is_consistency_only_and_big_decimals_remain_text() { observation_is_consistency_only_and_big_decimals_remain_text_body(); }

    pub(super) fn observation_is_consistency_only_and_big_decimals_remain_text_body() {
        let value = consistent();
        assert_eq!(serde_json::to_value(result(value.clone()).unwrap()).unwrap(), value);
        for flag in ["artifactBytesVerified", "workflowAuthenticated", "storeStateObserved", "comparedWithSourceProject", "releaseReady", "recoveryAuthorized"] {
            let mut bad = value.clone(); bad["assurance"][flag] = json!(true); assert!(result(bad).is_err());
        }
        for bad in [json!(9007199254740993u64), json!("01"), json!("0"), json!("1".repeat(65))] {
            let mut changed = value.clone(); changed["summary"]["artifacts"][0]["declaredBytes"] = bad; assert!(result(changed).is_err());
        }
        for bad in ["private\ncontent", "rtl\u{202e}name", "hidden\u{200b}name", "soft\u{00ad}name", "tag\u{e0001}name", "ab", ""] {
            let mut changed = value.clone(); changed["summary"]["applicationId"] = json!(bad); assert!(result(changed).is_err());
        }
        for (path, extra) in [("", "path"), ("summary", "fileName"), ("assurance", "authenticated")] {
            let mut changed = value.clone();
            if path.is_empty() { changed[extra] = json!("untrusted"); } else { changed[path][extra] = json!("untrusted"); }
            assert!(result(changed).is_err());
        }
        let mut bad = value.clone(); bad["documents"][0]["state"] = json!("missing"); assert!(result(bad).is_err());
        let mut bad = value.clone(); bad["summary"]["artifacts"].as_array_mut().unwrap().push(value["summary"]["artifacts"][0].clone()); assert!(result(bad).is_err());
    }
    #[test]
    fn core_result_fixtures_round_trip_without_native_normalization() { core_result_fixtures_round_trip_without_native_normalization_body(); }

    pub(super) fn core_result_fixtures_round_trip_without_native_normalization_body() {
        // The same five core-produced projections are consumed by the renderer
        // tests. This guards the cross-language contract, not provenance or IO.
        let fixtures: Value = serde_json::from_str(include_str!("../../tests/fixtures/candidate-evidence.json")).unwrap();
        let rows = fixtures.as_object().unwrap();
        assert_eq!(rows.len(), 5);
        for name in ["androidConsistent", "iosConsistent", "missingAll", "invalidManifestMissingOthers", "crossBindingMismatch"] {
            let value = rows.get(name).unwrap();
            let accepted = result(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(accepted).unwrap(), *value, "{name}");
        }
    }
    #[test]
    fn positional_nested_documents_and_noncanonical_summary_shapes_are_refused() { positional_nested_documents_and_noncanonical_summary_shapes_are_refused_body(); }

    pub(super) fn positional_nested_documents_and_noncanonical_summary_shapes_are_refused_body() {
        let value = consistent(); assert!(result(value.clone()).is_ok());
        for (pointer, positional) in [
            ("/documents/0", json!(["manifest", "valid"])),
            ("/summary/version", json!(["1.2.3",42])),
            ("/summary/source", json!(["a".repeat(40),"b".repeat(40)])),
            ("/summary/artifacts/0", json!(["android-aab","9007199254740993","c".repeat(64)])),
            ("/summary/recordedRuns/authorizedBy", json!(["9007199254740993","1"])),
            ("/summary/documentPayloadSha256", json!(["d".repeat(64),"e".repeat(64),"f".repeat(64)])),
            ("/assurance", json!(["local-document-consistency",true,false,false,false,false,false,false])),
        ] {
            let mut bad = value.clone(); *bad.pointer_mut(pointer).unwrap() = positional; assert!(result(bad).is_err(), "{pointer}");
        }
        for marketing in ["release", "1", "1.2+", "1.2.3.4.5", "1.2+rc+1"] {
            let mut bad = value.clone(); bad["summary"]["version"]["marketing"] = json!(marketing); assert!(result(bad).is_err());
        }
        for mutation in 0..3 {
            let mut bad = value.clone();
            match mutation {
                0 => { bad["summary"]["artifacts"].as_array_mut().unwrap().pop(); },
                1 => bad["summary"]["platform"] = json!("ios"),
                _ => bad["summary"]["artifacts"][0]["logicalName"] = json!("ios-ipa"),
            }
            assert!(result(bad).is_err());
        }
        assert!(display_text("Évidence 日本語",128,512));
        assert!(!display_text("Evidence\u{200b}",128,512));
    }
    #[test]
    fn failure_precedence_and_no_partial_summary_are_wire_contracts() { failure_precedence_and_no_partial_summary_are_wire_contracts_body(); }

    pub(super) fn failure_precedence_and_no_partial_summary_are_wire_contracts_body() {
        for (outcome, states) in [("incomplete", ["valid","missing","valid"]), ("invalid", ["invalid","missing","valid"]), ("inconsistent", ["valid","valid","valid"])] {
            let mut value = consistent(); value["outcome"] = json!(outcome); value["summary"] = Value::Null;
            for (i,state) in states.iter().enumerate() { value["documents"][i]["state"] = json!(state); }
            assert!(result(value.clone()).is_ok());
            value["summary"] = consistent()["summary"].clone(); assert!(result(value).is_err());
        }
        let mut missing = consistent(); missing.as_object_mut().unwrap().remove("summary"); assert!(result(missing).is_err());
        assert!(result(json!({"extra":vec![Value::Null;NODE_LIMIT]})).is_err());
        assert!(Status::unavailable(0).checked().is_ok());
        assert_eq!(core_problem(&BridgeError::new("artifacts_cleanup_unknown", "private")), Problem::CleanupUnknown);
        assert!(!refused(Problem::ObservationFailed).message.contains("private"));
    }
    #[test]
    fn status_cleanup_unknown_and_terminal_cancellation_cannot_be_relabelled() { status_cleanup_unknown_and_terminal_cancellation_cannot_be_relabelled_body(); }

    pub(super) fn status_cleanup_unknown_and_terminal_cancellation_cannot_be_relabelled_body() {
        let mut status = Status::unavailable(9); status.availability = "available"; status.phase = Phase::Unknown; status.problem = Some(Problem::CleanupUnknown);
        assert!(status.clone().checked().is_ok());
        for phase in [Phase::Idle, Phase::Refused, Phase::Cancelled, Phase::Stopping] {
            let mut bad = status.clone(); bad.phase = phase; assert!(bad.checked().is_err());
        }
        status.phase = Phase::Cancelled; status.problem = Some(Problem::Cancelled);
        assert!(status.clone().checked().is_err());
        status.operation = Some(Operation { operation_id: "9".to_owned(), kind: OperationKind::Choose, selection_id: None });
        assert!(status.clone().checked().is_ok());
        status.problem = Some(Problem::Deadline); assert!(status.checked().is_err());
    }
}
